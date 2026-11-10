'use strict';
(function () {
  const $ = id => document.getElementById(id);
  const KEYSTORE = 'arete.key';
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* private mode */ } },
    del(k) { try { localStorage.removeItem(k); } catch (e) { /* ignore */ } },
  };
  let DATA = null, DATES = [];
  let KEY = null, ENV = null; // the unlocked AES key and the envelope it opened (needed to save from the app, D059)
  let FLASH = '';
  let charts = [];
  const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
  const WD = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  // Colour rule (D066): blue, orange and green mean protein, carbs and fat and nothing else (D042).
  // Amber = off target, mint = on target. Everything else is ink on dark.
  const COL = { p: '#3987e5', c: '#d95926', f: '#199e70', pDim: 'rgba(57,135,229,.48)', ink: '#f3f0e9', bar: 'rgba(243,240,233,.82)', warn: '#f2b25c', good: '#7fe0b0',
    target: 'rgba(243,240,233,.6)', band: 'rgba(127,224,176,.13)', bandLine: 'rgba(127,224,176,.5)', grid: 'rgba(255,255,255,.07)', tick: '#a0a8bb' };

  const n0 = x => Math.round(x).toLocaleString('en-IN');
  const n1 = x => { const r = Math.round(x * 10) / 10; return Number.isInteger(r) ? String(r) : r.toFixed(1); };
  const esc = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const istToday = () => new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Kolkata' }).format(new Date());
  const addDays = (d, n) => { const x = new Date(d + 'T00:00:00Z'); x.setUTCDate(x.getUTCDate() + n); return x.toISOString().slice(0, 10); };
  const dow = d => (new Date(d + 'T00:00:00Z').getUTCDay() + 6) % 7; // Mon = 0
  const monday = d => addDays(d, -dow(d));
  const fmtShort = d => { const [, m, dd] = d.split('-').map(Number); return `${dd} ${MONTHS[m - 1].slice(0, 3)}`; };
  const fmtHrs = mins => { const m = Math.round(mins); return `${Math.floor(m / 60)}:${String(m % 60).padStart(2, '0')} hrs`; };
  const ABBR = { chest: 'Ch', back: 'Bk', biceps: 'Bi', bicep: 'Bi', shoulders: 'Sh', shoulder: 'Sh', triceps: 'Tri', tricep: 'Tri', legs: 'Legs', core: 'Core', arms: 'Arms' };
  const shortLabel = a => !a ? '' : a.replace(/^Gym\s*\W\s*/, '').split(/\s*[\/,&+]\s*/).map(w => ABBR[w.toLowerCase()] || w).join('·');
  const sep = '<span class="sep"> · </span>';

  // Phase 5 (D003, D054): data.enc.json is AES-GCM encrypted; the key comes from the
  // passphrase via PBKDF2. The key (never the passphrase) is remembered on this device:
  // IndexedDB as a non-extractable key, or localStorage if IndexedDB is not available.
  const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const b64e = buf => { let s = ''; new Uint8Array(buf).forEach(b => { s += String.fromCharCode(b); }); return btoa(s); };
  const idb = {
    open() { return new Promise((ok, no) => { const r = indexedDB.open('arete', 1); r.onupgradeneeded = () => r.result.createObjectStore('k'); r.onsuccess = () => ok(r.result); r.onerror = () => no(r.error); }); },
    async run(mode, fn) { const db = await idb.open(); return new Promise((ok, no) => { const tx = db.transaction('k', mode); const req = fn(tx.objectStore('k')); tx.oncomplete = () => ok(req && req.result); tx.onerror = () => no(tx.error); tx.onabort = () => no(tx.error); }); },
    get: k => idb.run('readonly', s => s.get(k)),
    set: (k, v) => idb.run('readwrite', s => s.put(v, k)),
    del: k => idb.run('readwrite', s => s.delete(k)),
  };
  async function deriveBits(pass, env) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveBits']);
    return crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: b64d(env.salt), iterations: env.iter }, base, 256);
  }
  // encrypt too: the Add form re-encrypts the site data after a save (D059).
  const aesKey = bits => crypto.subtle.importKey('raw', bits, 'AES-GCM', false, ['encrypt', 'decrypt']);
  async function decrypt(key, env) {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64d(env.iv) }, key, b64d(env.ct));
    return JSON.parse(new TextDecoder().decode(pt));
  }
  async function remember(bits, key) {
    try { await idb.set(KEYSTORE, key); store.del(KEYSTORE); return; } catch (e) { /* fall back */ }
    store.set(KEYSTORE, b64e(bits));
  }
  async function recall() {
    try { const k = await idb.get(KEYSTORE); if (k) return k; } catch (e) { /* none */ }
    const raw = store.get(KEYSTORE);
    if (raw) { try { return await aesKey(b64d(raw)); } catch (e) { /* bad */ } }
    return null;
  }
  async function forget() {
    try { await idb.del(KEYSTORE); } catch (e) { /* ignore */ }
    store.del(KEYSTORE); store.del('arete.unlock');
  }
  function opened(d) { DATA = d; DATES = Object.keys(DATA.days).sort(); $('lock').hidden = true; start(); }

  function fail(text, canRetry) {
    $('lock').hidden = true; $('app').hidden = true; $('fail').hidden = false;
    $('failMsg').textContent = text;
    $('retry').hidden = !canRetry; $('retry').onclick = () => location.reload();
  }

  async function boot() {
    store.del('arete.unlock'); // old passcode gate (D037, retired)
    let env;
    try {
      const r = await fetch('data.enc.json?v=' + Date.now(), { cache: 'no-store' });
      if (!r.ok) throw new Error(r.status);
      env = await r.json();
    } catch (e) { return fail('Could not load your data. Check the connection, then try again.', true); }
    if (!window.crypto || !crypto.subtle) return fail('This browser cannot unlock Arete. Open it in an up-to-date Chrome or Safari.', false);
    const saved = await recall();
    ENV = env;
    if (saved) { try { const d = await decrypt(saved, env); KEY = saved; return opened(d); } catch (e) { await forget(); } }
    $('lock').hidden = false;
    $('pass').focus();
    $('lockForm').onsubmit = async ev => {
      ev.preventDefault();
      const btn = $('lockForm').querySelector('button');
      btn.disabled = true; $('lockMsg').textContent = '';
      try {
        const bits = await deriveBits($('pass').value, env);
        const key = await aesKey(bits);
        const d = await decrypt(key, env);
        await remember(bits, key);
        KEY = key;
        $('pass').value = '';
        opened(d);
      } catch (e) { $('lockMsg').textContent = 'Wrong passphrase'; $('pass').select(); }
      finally { btn.disabled = false; }
    };
  }

  // ---------- shell: start, routes, navigation ----------
  let depth = 0; // in-app navigations since load, so Back never leaves the app
  function start() {
    $('app').hidden = false;
    $('lockBtn').onclick = async () => { await forget(); location.hash = ''; location.reload(); };
    $('back').onclick = () => {
      const r = route();
      if (r.view === 'bodyadd') location.hash = '#/b';
      else if (depth > 0) history.back();
      else location.hash = r.view === 'day' ? '#/m/' + r.date.slice(0, 7) : '#/t';
    };
    document.querySelectorAll('#tabs button').forEach(b => { b.onclick = () => go(b.dataset.v); });
    window.addEventListener('hashchange', () => { depth++; render(); });
    if (window.Chart) {
      const D = Chart.defaults;
      D.color = COL.tick; D.borderColor = COL.grid;
      D.font.family = getComputedStyle(document.body).fontFamily; D.font.size = 11;
      D.animation = false;
      Object.assign(D.plugins.tooltip, { backgroundColor: '#161a27', borderColor: 'rgba(255,255,255,.14)', borderWidth: 1, titleColor: COL.ink, bodyColor: COL.ink,
        padding: 10, cornerRadius: 10, displayColors: false });
      D.plugins.legend.display = false;
    }
    // Charts measure text with the page font, so wait for it (briefly) before the first draw.
    const fonts = document.fonts && document.fonts.ready ? document.fonts.ready : Promise.resolve();
    Promise.race([fonts, new Promise(r => setTimeout(r, 1200))]).then(render, render);
  }

  function lastDate() { return DATES[DATES.length - 1]; }
  function go(view) {
    const r = route(); const anchor = r.date || r.from || (r.month ? r.month + '-01' : lastDate());
    if (view === 'month') location.hash = '#/m/' + anchor.slice(0, 7);
    if (view === 'week') location.hash = '#/w/' + monday(anchor > lastDate() ? lastDate() : anchor);
    if (view === 'range') { const to = lastDate(); location.hash = `#/r/${addDays(to, -13)}/${to}`; }
    if (view === 'body') location.hash = '#/b';
    if (view === 'train') location.hash = '#/t';
  }

  const isD = s => /^\d{4}-\d{2}-\d{2}$/.test(s || '');
  function route() {
    const h = location.hash.replace(/^#\/?/, '').split('/');
    if (h[0] === 'd' && DATA.days[h[1]]) return { view: 'day', date: h[1], tab: 'month' };
    if (h[0] === 'b' && h[1] === 'add') return { view: 'bodyadd', tab: 'body', date: isD(h[2]) ? h[2] : null };
    if (h[0] === 'b') return { view: 'body' };
    if (h[0] === 't' && h[1] === 's' && h[2]) return { view: 'session', id: h[2], tab: 'train' };
    if (h[0] === 't' && h[1] === 'x' && h[2]) { let ex = h[2]; try { ex = decodeURIComponent(h[2]); } catch (e) { /* keep raw */ } return { view: 'exercise', ex, tab: 'train' }; }
    if (h[0] === 't') return { view: 'train' };
    if (h[0] === 'm' && /^\d{4}-\d{2}$/.test(h[1])) return { view: 'month', month: h[1] };
    if (h[0] === 'w' && isD(h[1])) return { view: 'week', from: monday(h[1]) };
    if (h[0] === 'r' && isD(h[1]) && isD(h[2])) { const [a, b] = [h[1], h[2]].sort(); return { view: 'range', from: a, to: b }; }
    const t = istToday().slice(0, 7);
    return { view: 'month', month: DATES.some(d => d.startsWith(t)) ? t : lastDate().slice(0, 7) };
  }

  function render() {
    charts.forEach(c => c.destroy()); charts = [];
    const r = route();
    const sub = r.view === 'day' || r.view === 'session' || r.view === 'exercise' || r.view === 'bodyadd';
    $('back').hidden = !sub;
    $('tabs').hidden = r.view === 'bodyadd'; // the form has its own Save bar there
    document.querySelectorAll('#tabs button').forEach(b => {
      const on = b.dataset.v === (r.tab || r.view);
      b.classList.toggle('on', on);
      if (on) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
    });
    window.scrollTo(0, 0);
    if (r.view === 'day') renderDay(r.date);
    else if (r.view === 'week') renderPeriod(r.from, addDays(r.from, 6), 'week');
    else if (r.view === 'range') renderPeriod(r.from, r.to, 'range');
    else if (r.view === 'body') renderBody();
    else if (r.view === 'bodyadd') renderBodyAdd(r.date);
    else if (r.view === 'train') renderTraining(false);
    else if (r.view === 'session') renderSession(r.id);
    else if (r.view === 'exercise') renderExercise(r.ex);
    else renderMonth(r.month);
    wire();
  }

  // Anything with data-go opens that view; table rows also work from the keyboard.
  function wire() {
    $('view').querySelectorAll('[data-go]').forEach(el => {
      el.onclick = () => { location.hash = el.dataset.go; };
      if (el.tagName === 'TR') {
        el.tabIndex = 0; el.setAttribute('role', 'link');
        el.onkeydown = e => { if (e.key === 'Enter') location.hash = el.dataset.go; };
      }
    });
    $('view').querySelectorAll('button[data-csv]').forEach(b => { b.onclick = () => exportCSV(b.dataset.csv, b.dataset.from, b.dataset.to); });
  }

  // ---------- small building blocks ----------
  const ICON = {
    l: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M15 5l-7 7 7 7"/></svg>',
    r: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9 5l7 7-7 7"/></svg>',
  };
  const navBtn = (dir, label, to) => `<button class="iconbtn" aria-label="${label}"${to ? ` data-go="${to}"` : ' disabled'}>${ICON[dir]}</button>`;
  const phead = (title, sub, right) => `<div class="phead"><h1 class="title">${title}${sub ? `<small>${sub}</small>` : ''}</h1>${right ? `<div class="navs">${right}</div>` : ''}</div>`;
  const pill = (label, value) => `<span class="pill">${label}${value != null && value !== '' ? ` <b>${value}</b>` : ''}</span>`;
  const pct = x => Math.max(0, Math.min(100, x * 100)).toFixed(1);
  const fmtLong = d => `${WD[dow(d)]} ${fmtShort(d)} ${d.slice(0, 4)}`;
  const macroLine = t => `<b>${n0(t.kcal)}</b> kcal${sep}<i class="mp">P</i> ${n0(t.p)}${sep}<i class="mc">C</i> ${n0(t.c)}${sep}<i class="mf">F</i> ${n0(t.f)}`;

  // kcal and protein against the target: a bar with the target marked on it.
  function gaugesHTML(v, t) {
    if (!t) return '';
    const over = v.kcal > t.kcal, dk = Math.round(v.kcal - t.kcal);
    const kTxt = dk === 0 ? `on the ${n0(t.kcal)} target` : `${n0(Math.abs(dk))} ${dk > 0 ? 'over' : 'under'} the ${n0(t.kcal)} target`;
    const scale = t.proteinMax * 1.25;
    const low = v.p < t.proteinMin;
    const pTxt = low ? `${Math.ceil(t.proteinMin - v.p)} g short of ${t.proteinMin}` : v.p > t.proteinMax ? `above ${t.proteinMin} to ${t.proteinMax} g` : `within ${t.proteinMin} to ${t.proteinMax} g`;
    return `<div class="gauges">` +
      `<div class="g"><div class="gl"><span>Calories</span><span class="${over ? 'warn' : ''}">${kTxt}</span></div>` +
        `<div class="gauge"><div class="fill${over ? ' warn' : ''}" style="width:${pct(v.kcal / (t.kcal * 1.5))}%"></div><i class="tick" style="left:66.667%"></i></div></div>` +
      `<div class="g"><div class="gl"><span>Protein</span><span class="${low ? 'warn' : 'good'}">${pTxt}</span></div>` +
        `<div class="gauge"><i class="band" style="left:${pct(t.proteinMin / scale)}%;width:${pct((t.proteinMax - t.proteinMin) / scale)}%"></i>` +
        `<div class="fill p" style="width:${pct(v.p / scale)}%"></div></div></div></div>`;
  }

  // Macro split: ring plus each macro's share of the calories.
  function splitHTML(id, t) {
    const k = [t.p * 4, t.c * 4, t.f * 9]; const sum = k[0] + k[1] + k[2] || 1;
    const row = (c, name, i) => `<div><i class="sw ${c}"></i><span>${name}</span><b>${Math.round(k[i] / sum * 100)}%</b></div>`;
    return `<div class="split"><div class="ring"><canvas id="${id}" role="img" aria-label="Macro split, share of calories"></canvas></div>` +
      `<div class="legend-m"><div class="lh">Share of calories</div>${row('p', 'Protein', 0)}${row('c', 'Carbs', 1)}${row('f', 'Fat', 2)}</div></div>`;
  }
  function drawDonut(canvasId, t) {
    if (!window.Chart || !$(canvasId)) return;
    const k = [t.p * 4, t.c * 4, t.f * 9];
    charts.push(new Chart($(canvasId), {
      type: 'doughnut',
      data: { labels: ['Protein', 'Carbs', 'Fat'], datasets: [{ data: k.map(Math.round), backgroundColor: [COL.p, COL.c, COL.f], borderWidth: 0, spacing: 2, borderRadius: 3 }] },
      options: { responsive: true, maintainAspectRatio: false, cutout: '66%', plugins: { tooltip: { callbacks: { label: c => `${n0(c.parsed)} kcal` } } } },
    }));
  }

  // ---------- shared period pieces ----------
  function daysIn(from, to) { return DATES.filter(d => d >= from && d <= to).map(d => DATA.days[d]); }

  function stats(days) {
    const n = days.length;
    const t = { kcal: 0, p: 0, c: 0, f: 0 };
    days.forEach(d => { for (const k in t) t[k] += d.totals[k]; });
    const avg = n ? { kcal: t.kcal / n, p: t.p / n, c: t.c / n, f: t.f / n } : t;
    const fasts = days.filter(d => d.fast).map(d => d.fast.minutes);
    const tgt = n ? days[n - 1].target : null;
    return {
      n, avg, tgt, trained: days.filter(d => d.workout.trained).length,
      avgFast: fasts.length ? fmtHrs(fasts.reduce((a, b) => a + b, 0) / fasts.length) : null,
      overKcal: days.filter(d => d.target && d.totals.kcal > d.target.kcal).length,
      proteinHit: days.filter(d => d.target && d.totals.p >= d.target.proteinMin).length,
    };
  }

  function summaryHTML(id, s, from, to) {
    if (!s.n) return `<section class="card hero"><div class="empty">No food logged in this period.</div></section>`;
    const t = s.tgt;
    return `<section class="card hero"><div class="cap">Daily average over ${s.n} logged day${s.n > 1 ? 's' : ''}</div>` +
      `<div class="macros">${macroLine(s.avg)}</div>${gaugesHTML(s.avg, t)}${splitHTML(id + 'd', s.avg)}` +
      `<div class="pills">${t ? pill('Over kcal target', `${s.overKcal} of ${s.n}`) + pill(`Protein ${t.proteinMin} g or more`, `${s.proteinHit} of ${s.n}`) : ''}` +
      `${pill('Trained', `${s.trained} of ${s.n}`)}${s.avgFast ? pill('Average fast', s.avgFast) : ''}</div>` +
      `<div class="acts"><button class="btn sm" data-csv="days" data-from="${from}" data-to="${to}">Days CSV</button><button class="btn sm" data-csv="items" data-from="${from}" data-to="${to}">Items CSV</button></div></section>`;
  }

  function chartsHTML(id, s) {
    if (!s.n) return '';
    const t = s.tgt;
    return `<section class="card chart"><h3><span>Calories per day</span><span class="aside">${t ? `dashed line: ${n0(t.kcal)} target` : ''}</span></h3><div class="cbox"><canvas id="${id}k"></canvas></div></section>` +
      `<section class="card chart"><h3><span>Protein per day</span><span class="aside">${t ? `band: ${t.proteinMin} to ${t.proteinMax} g` : ''}</span></h3><div class="cbox"><canvas id="${id}p"></canvas></div></section>`;
  }

  function drawPeriodCharts(id, days, s, labelFn) {
    drawDonut(id + 'd', s.avg);
    if (!window.Chart || !days.length) return;
    const labels = days.map(labelFn);
    const scales = { x: { grid: { display: false }, border: { display: false }, ticks: { maxRotation: 0, autoSkip: true, autoSkipPadding: 6 } },
      y: { beginAtZero: true, grid: { color: COL.grid }, border: { display: false }, ticks: { maxTicksLimit: 6 } } };
    const flat = (v, extra) => Object.assign({ type: 'line', data: days.map(d => (d.target ? v(d.target) : null)), borderWidth: 1.2, pointRadius: 0, pointHitRadius: 0, order: 0, spanGaps: true }, extra);
    const bars = (data, colors) => ({ type: 'bar', data, backgroundColor: colors, borderRadius: 5, borderSkipped: 'bottom', maxBarThickness: 22, categoryPercentage: .82, barPercentage: .88, order: 1 });
    const opts = unit => ({ responsive: true, maintainAspectRatio: false, scales, interaction: { mode: 'index', intersect: false },
      plugins: { tooltip: { filter: c => c.dataset.type === 'bar', callbacks: { label: c => `${n0(c.parsed.y)} ${unit}` } } },
      onClick: (e, els) => { if (els.length) location.hash = '#/d/' + days[els[0].index].date; } });
    // Calories: bars turn amber on days over the target.
    charts.push(new Chart($(id + 'k'), { data: { labels, datasets: [
      bars(days.map(d => d.totals.kcal), days.map(d => (d.target && d.totals.kcal > d.target.kcal ? COL.warn : COL.bar))),
      flat(t => t.kcal, { borderColor: COL.target, borderDash: [4, 4] })] }, options: opts('kcal') }));
    // Protein: the target range is a band; days under the minimum are faded.
    charts.push(new Chart($(id + 'p'), { data: { labels, datasets: [
      bars(days.map(d => d.totals.p), days.map(d => (d.target && d.totals.p < d.target.proteinMin ? COL.pDim : COL.p))),
      flat(t => t.proteinMin, { borderColor: COL.bandLine, fill: '+1', backgroundColor: COL.band }),
      flat(t => t.proteinMax, { borderColor: COL.bandLine })] }, options: opts('g protein') }));
  }

  function dayTableHTML(days) {
    if (!days.length) return '';
    const rows = days.map(d => `<tr data-go="#/d/${d.date}"><td class="item">${d.weekday.slice(0, 3)} ${fmtShort(d.date)}<span class="pl">${d.workout.trained ? esc(shortLabel(d.workout.area) || 'Trained') : 'Rest'}</span></td>` +
      `<td class="${d.target && d.totals.kcal > d.target.kcal ? 'warn' : ''}">${n0(d.totals.kcal)}</td><td class="${d.target ? (d.totals.p < d.target.proteinMin ? '' : 'good') : ''}">${n0(d.totals.p)}</td>` +
      `<td>${n0(d.totals.c)}</td><td>${n0(d.totals.f)}</td><td class="q">${d.fast ? d.fast.text.replace(' hrs', '') : ''}</td></tr>`).join('');
    return `<section class="card"><h3><span>Days</span><span class="aside">tap a day to open it</span></h3><table class="days"><colgroup><col><col class="c-k2"><col class="c-m"><col class="c-m"><col class="c-m"><col class="c-qty"></colgroup>` +
      `<thead><tr><th>Day</th><th>kcal</th><th>P</th><th>C</th><th>F</th><th>Fast</th></tr></thead><tbody>${rows}</tbody></table></section>`;
  }

  // ---------- pantry strip (D043) ----------
  function pantryHTML() {
    const P = (DATA.pantry || []).filter(p => p.stockG != null);
    if (!P.length) return '';
    const ref = lastDate();
    const rank = p => (p.low ? 0 : 1) * 1e6 + (p.daysLeft == null ? 9e5 : p.daysLeft);
    const chips = P.slice().sort((a, b) => rank(a) - rank(b)).map(p => {
      const old = p.asOf < addDays(ref, -14); // count is more than two weeks older than the last logged day
      return `<div class="chip${p.low ? ' low' : ''}${old ? ' old' : ''}"><div class="pn">${esc(p.name)}</div>` +
        `<div class="pv">${n0(p.stockG)}<span class="u">g</span></div><div class="pd">${p.low ? 'Low: ' : ''}${p.daysLeft != null ? `about ${p.daysLeft} days left` : 'no recent use'}</div>` +
        `<div class="pa">${old ? 'old count, ' : 'counted '}${fmtShort(p.asOf)}</div></div>`;
    }).join('');
    const lows = P.filter(p => p.low).length;
    return `<div class="sect"><span>Pantry</span><span class="aside${lows ? ' warn' : ''}">${lows ? `${lows} running low` : 'stock and days left'}</span></div><div class="strip" aria-label="Pantry">${chips}</div>`;
  }

  // ---------- views ----------
  function renderMonth(m) {
    const [y, mo] = m.split('-').map(Number);
    const first = `${m}-01`;
    const nDays = new Date(Date.UTC(y, mo, 0)).getUTCDate();
    const last = `${m}-${String(nDays).padStart(2, '0')}`;
    const lead = dow(first);
    const prevM = new Date(Date.UTC(y, mo - 2, 1)).toISOString().slice(0, 7);
    const nextM = new Date(Date.UTC(y, mo, 1)).toISOString().slice(0, 7);
    const minM = DATES[0].slice(0, 7), maxM = [lastDate().slice(0, 7), istToday().slice(0, 7)].sort()[1];
    const today = istToday();
    const sess = {}; T().sessions.forEach(s => { if (!sess[s.date]) sess[s.date] = s; });
    let cells = WD.map(w => `<div class="wd">${w}</div>`).join('');
    for (let i = 0; i < lead; i++) cells += '<div class="cell blank"></div>';
    for (let d = 1; d <= nDays; d++) {
      const date = `${m}-${String(d).padStart(2, '0')}`;
      const day = DATA.days[date];
      const now = date === today ? ' today' : '';
      if (!day) { // no food logged: still show a workout if there was one
        const s = sess[date];
        cells += s ? `<button class="cell nolog${now}" data-go="#/t/s/${s.id}" aria-label="${d} ${MONTHS[mo - 1]}, trained ${esc(s.label || '')}, food not logged"><span class="dn">${d}</span><span class="tg">${esc(shortLabel(s.label) || 'Trained')}</span></button>`
          : `<div class="cell nodata${now}"><span class="dn">${d}</span></div>`;
        continue;
      }
      const t = day.target;
      const over = t && day.totals.kcal > t.kcal, hit = t && day.totals.p >= t.proteinMin;
      const tag = day.workout.trained ? esc(shortLabel(day.workout.area) || 'Trained') : '';
      cells += `<button class="cell${now}" data-go="#/d/${date}" aria-label="${d} ${MONTHS[mo - 1]}, ${n0(day.totals.kcal)} kcal${over ? ' over target' : ''}, protein ${n0(day.totals.p)} g${tag ? ', trained' : ', rest day'}">` +
        `<span class="dn">${d}</span><span class="k${over ? ' warn' : ''}">${n0(day.totals.kcal)}</span><span class="pv${hit ? ' good' : ''}"><i>P</i>${n0(day.totals.p)}</span><span class="tg">${tag}</span></button>`;
    }
    const days = daysIn(first, last); const s = stats(days);
    const t = s.tgt;
    $('view').innerHTML =
      phead(MONTHS[mo - 1], String(y), navBtn('l', 'Previous month', prevM < minM ? '' : '#/m/' + prevM) + navBtn('r', 'Next month', nextM > maxM ? '' : '#/m/' + nextM)) +
      `<div class="cal">${cells}</div>` +
      (t ? `<div class="legend"><span><i class="dot warn"></i>over the ${n0(t.kcal)} kcal target</span><span><i class="dot good"></i>protein ${t.proteinMin} g or more</span></div>` : '') +
      summaryHTML('mc', s, first, last) + pantryHTML() + chartsHTML('mc', s) +
      `<div class="foot">Food logged up to ${fmtLong(lastDate())}<br>Updated ${esc(DATA.updated || '')}</div>`;
    drawPeriodCharts('mc', days, s, d => String(Number(d.date.slice(8))));
  }

  function renderPeriod(from, to, kind) {
    const days = daysIn(from, to); const s = stats(days);
    let head;
    if (kind === 'week') {
      const pw = addDays(from, -7), nw = addDays(from, 7);
      head = phead(`${fmtShort(from)} to ${fmtShort(to)}`, `Week, Monday to Sunday, ${to.slice(0, 4)}`,
        navBtn('l', 'Previous week', addDays(from, -1) < DATES[0] ? '' : '#/w/' + pw) + navBtn('r', 'Next week', nw > lastDate() ? '' : '#/w/' + nw));
    } else {
      const span = Math.round((Date.parse(to) - Date.parse(from)) / 864e5) + 1;
      const presets = [[7, '7 days'], [14, '14 days'], [30, '30 days'], [0, 'All']];
      const t = lastDate();
      head = phead(`${fmtShort(from)} to ${fmtShort(to)}`, `${span} day${span > 1 ? 's' : ''}, ${from.slice(0, 4) === to.slice(0, 4) ? to.slice(0, 4) : from.slice(0, 4) + ' to ' + to.slice(0, 4)}`) +
        `<div class="presets">${presets.map(([n, l]) => { const f = n ? addDays(t, -(n - 1)) : DATES[0]; const f2 = f < DATES[0] ? DATES[0] : f;
          return `<button class="btn sm${from === f2 && to === t ? ' on' : ''}" data-go="#/r/${f2}/${t}">${l}</button>`; }).join('')}</div>` +
        `<div class="range"><label>From<input type="date" id="rf" value="${from}" min="${DATES[0]}" max="${t}"></label>` +
        `<label>To<input type="date" id="rt" value="${to}" min="${DATES[0]}" max="${t}"></label><button class="btn" id="ra">Show</button></div>`;
    }
    const label = kind === 'week' ? d => d.weekday.slice(0, 3) : d => fmtShort(d.date);
    $('view').innerHTML = head + summaryHTML('pc', s, from, to) + chartsHTML('pc', s) + dayTableHTML(days);
    if ($('ra')) $('ra').onclick = () => { if ($('rf').value && $('rt').value) location.hash = `#/r/${$('rf').value}/${$('rt').value}`; };
    drawPeriodCharts('pc', days, s, label);
  }

  // Optional metrics: shown only when switched on in settings.json (D011, D048).
  function metricsHTML(d) {
    const F = DATA.settings.optionalMetrics;
    if (!DATA.settings.optionalMetricsEnabled || !F || !d.metrics) return '';
    return Object.entries(F).filter(([k]) => d.metrics[k] != null).map(([k, f]) =>
      pill(esc(f.label), `${Array.isArray(d.metrics[k]) ? esc(d.metrics[k].join(', ')) : (k === 'steps' ? n0(d.metrics[k]) : n1(d.metrics[k]))}${f.unit ? ' ' + esc(f.unit) : ''}`)).join('');
  }

  function renderDay(date) {
    const d = DATA.days[date];
    const i = DATES.indexOf(date);
    const prev = DATES[i - 1], next = DATES[i + 1];
    const [y, mo, dd] = date.split('-').map(Number);
    const w = d.workout.trained ? pill(esc(d.workout.area || 'Trained'), d.workout.time ? esc(d.workout.time) : '') : pill('Rest day');
    const fast = d.fast ? pill('Fast', esc(d.fast.text) + (d.fast.override ? ' (manual)' : '')) : '';
    const links = (d.sessions || []).map(id => `<a class="pill link" href="#/t/s/${id}">Workout sets</a>`).join('') + `<a class="pill link" href="#/w/${monday(date)}">This week</a>`;
    const flags = d.flags.length ? `<div class="flags">${d.flags.map(f => `<div>${esc(f)}</div>`).join('')}</div>` : '';
    const cards = d.cards.map(c => {
      const rows = c.items.map(it => `<tr><td class="item">${esc(it.name)}${it.estimate ? '<span class="est" title="estimate">est</span>' : ''}` +
        `${it.place ? `<span class="pl">${esc(it.place)}</span>` : ''}</td><td class="q">${n1(it.qty)} ${esc(it.unit)}</td>` +
        `<td>${n0(it.kcal)}</td><td>${n1(it.p)}</td><td>${n1(it.c)}</td><td>${n1(it.f)}</td></tr>`).join('');
      const tot = c.items.length > 1 ? `<tr class="tot"><td class="item">Total</td><td></td><td>${n0(c.totals.kcal)}</td><td>${n1(c.totals.p)}</td><td>${n1(c.totals.c)}</td><td>${n1(c.totals.f)}</td></tr>` : '';
      return `<section class="card"><h3><span>${esc(c.meal)}</span><span class="aside">${c.time ? esc(c.time) + ' IST' : 'whole day'}</span></h3>` +
        `<table><colgroup><col><col class="c-qty"><col class="c-k"><col class="c-m"><col class="c-m"><col class="c-f"></colgroup>` +
        `<thead><tr><th>Item</th><th>Qty</th><th>kcal</th><th>P</th><th>C</th><th>F</th></tr></thead><tbody>${rows}${tot}</tbody></table></section>`;
    }).join('');
    $('view').innerHTML =
      phead(d.weekday, `${dd} ${MONTHS[mo - 1]} ${y}`, navBtn('l', 'Previous day', prev ? '#/d/' + prev : '') + navBtn('r', 'Next day', next ? '#/d/' + next : '')) +
      `<section class="card hero"><div class="macros">${macroLine(d.totals)}</div>${gaugesHTML(d.totals, d.target)}${splitHTML('dd', d.totals)}` +
      `<div class="pills">${fast}${w}${metricsHTML(d)}${links}</div>${flags}</section>` +
      cards + `<div class="acts end"><button class="btn sm" data-csv="items" data-from="${date}" data-to="${date}">Day CSV</button></div>`;
    drawDonut('dd', d.totals);
  }

  // ---------- body ----------
  const bl = (B, k) => (B.labels && B.labels[k]) || k;
  const unitOf = (B, k) => k === 'weightKg' ? 'kg' : 'cm';
  const signed = (x, u) => x == null ? '' : `${x > 0 ? '+' : x < 0 ? '−' : '±'}${n1(Math.abs(x))}${u ? ' ' + u : ''}`;
  // Lean gain: a growing waist is the one to watch, a shrinking one is good. The sign is always shown too.
  function cls(k, d) { if (d == null || d === 0) return 'q'; if (k === 'waist') return d > 0 ? 'warn' : 'good'; return ''; }

  function renderBody() {
    const B = DATA.body;
    const flash = FLASH ? `<div class="flash" role="status">${esc(FLASH)}</div>` : '';
    FLASH = '';
    const addBtn = `<button class="btn primary" data-go="#/b/add">Add measurements</button>`;
    if (!B || !B.entries.length) {
      const parts = B ? [...new Set(B.fields.map(k => bl(B, k).replace(/ [LR]$/, '').toLowerCase()))].join(', ') : '';
      $('view').innerHTML = phead('Body', B && B.goal ? `Goal: ${B.goal.weightKg} kg, lean gain` : '') + flash +
        `<section class="card hero"><div class="empty">No measurements yet.</div><div class="cap">Once a week: ${esc(parts)}.</div><div class="acts">${addBtn}</div></section>`;
      return;
    }
    const E = B.entries, last = E[E.length - 1];
    const w = B.latest.weightKg, w0 = B.first.weightKg;
    let goal = '';
    if (w && B.goal) {
      const g = B.goal.weightKg, start = Math.min(w0.value, w.value, g - 0.1);
      const done = B.toGoalKg <= 0;
      goal = `<div class="gauges one"><div class="g"><div class="gl"><span>Goal ${g} kg</span><span class="${done ? 'good' : ''}">${done ? 'reached' : n1(B.toGoalKg) + ' kg to go'}</span></div>` +
        `<div class="gauge"><div class="fill${done ? ' good' : ''}" style="width:${pct(Math.max(0.02, (w.value - start) / (g - start)))}%"></div><i class="tick" style="left:100%"></i></div></div></div>`;
    }
    const head = `<section class="card hero"><div class="cap">Latest, ${fmtLong(last.date)}</div>` +
      (w ? `<div class="big">${n1(w.value)}<span class="u">kg</span></div>` : '') + goal +
      `<div class="pills">${last.d.weightKg != null ? pill('Since last', signed(last.d.weightKg, 'kg')) : ''}` +
      (w && w0 && w0.date !== w.date ? pill(`Since ${fmtShort(w0.date)}`, signed(w.value - w0.value, 'kg')) : '') +
      (B.latest.waist ? pill('Waist', n1(B.latest.waist.value) + ' cm') : '') +
      (last.conditions ? pill(esc(last.conditions)) : '') + (last.biceps ? pill('Biceps', esc(last.biceps)) : '') + `</div>` +
      `<div class="acts">${addBtn}</div></section>`;
    const pair = `<div class="pair"><section class="card chart"><h3><span>Weight</span><span class="aside">kg</span></h3><div class="cbox sm"><canvas id="bw"></canvas></div></section>` +
      `<section class="card chart"><h3><span>Waist</span><span class="aside">cm</span></h3><div class="cbox sm"><canvas id="bwa"></canvas></div></section></div>`;
    const rows = B.fields.filter(k => B.latest[k]).map(k => {
      const L = B.latest[k], F = B.first[k], u = unitOf(B, k);
      const dPrev = E.slice().reverse().find(e => e.v[k] != null).d[k];
      const dFirst = F.date !== L.date ? L.value - F.value : null;
      return `<tr><td class="item">${esc(bl(B, k))}</td><td>${n1(L.value)}</td><td class="${cls(k, dPrev)}">${signed(dPrev)}</td>` +
        `<td class="${cls(k, dFirst)}">${signed(dFirst)}</td><td class="q">${u}</td></tr>`;
    }).join('');
    const table = `<section class="card"><h3><span>Measurements</span><span class="aside">change since last and first</span></h3>` +
      `<table><colgroup><col><col class="c-k2"><col class="c-k2"><col class="c-k2"><col class="c-u"></colgroup>` +
      `<thead><tr><th>Part</th><th>Now</th><th>Last</th><th>First</th><th></th></tr></thead><tbody>${rows}</tbody></table></section>`;
    const hist = `<section class="card"><h3><span>History</span><span class="aside">tap an entry to view or change it</span></h3>` +
      `<table class="days"><colgroup><col><col class="c-k2"><col class="c-k2"></colgroup><thead><tr><th>Date</th><th>kg</th><th>Waist</th></tr></thead><tbody>` +
      E.slice().reverse().map(e => `<tr data-go="#/b/add/${e.date}"><td class="item">${fmtLong(e.date)}${e.conditions ? `<span class="pl">${esc(e.conditions)}</span>` : ''}</td>` +
        `<td>${e.v.weightKg != null ? n1(e.v.weightKg) : ''}</td><td>${e.v.waist != null ? n1(e.v.waist) : ''}</td></tr>`).join('') + `</tbody></table></section>`;
    $('view').innerHTML = phead('Body', B.goal ? `Goal: ${B.goal.weightKg} kg, lean gain` : '') + flash + head + pair + table + hist +
      `<div class="acts end"><button class="btn sm" id="bcsv">Body CSV</button></div>`;
    $('bcsv').onclick = () => {
      const r = [['date', 'time', 'conditions', 'biceps', ...B.fields.map(k => `${k}_${unitOf(B, k)}`), 'note']];
      E.forEach(e => r.push([e.date, e.time || '', e.conditions || '', e.biceps || '', ...B.fields.map(k => e.v[k] ?? ''), e.note || '']));
      download('arete-body.csv', r);
    };
    // Weight and waist side by side (D021).
    const lineChart = (id, k, extra) => {
      const pts = E.filter(e => e.v[k] != null);
      if (!window.Chart || !pts.length) return;
      charts.push(new Chart($(id), { type: 'line', data: { labels: pts.map(e => fmtShort(e.date)), datasets: [
        { label: bl(B, k), data: pts.map(e => e.v[k]), borderColor: COL.ink, backgroundColor: COL.ink, borderWidth: 2, pointRadius: 3, tension: .25, cubicInterpolationMode: 'monotone' }, ...(extra || [])] },
        options: { responsive: true, maintainAspectRatio: false,
          scales: { x: { grid: { display: false }, border: { display: false }, ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 4 } }, y: { grid: { color: COL.grid }, border: { display: false }, grace: '5%', ticks: { maxTicksLimit: 5 } } } } }));
    };
    const wp = E.filter(e => e.v.weightKg != null);
    lineChart('bw', 'weightKg', B.goal ? [{ label: 'Goal', data: wp.map(() => B.goal.weightKg), borderColor: COL.good, borderDash: [4, 4], borderWidth: 1.5, pointRadius: 0 }] : []);
    lineChart('bwa', 'waist');
  }

  // ---------- Body: Add form, saves straight to GitHub (D057, D059) ----------
  // 1) the raw entry goes to arete data/inbox/body-<date>.json (the record; build.js merges it),
  // 2) the latest site data is fetched, decrypted with this device's key, updated with the SAME
  //    code the build uses (shared.js), re-encrypted and pushed to arete-site.
  // The GitHub key is pasted once per device and kept only in this browser (localStorage).
  const GH = 'https://api.github.com/repos/sanjaykandampully/';
  const GHKEY = 'arete.gh';
  const nowIST = () => new Intl.DateTimeFormat('en-GB', { timeZone: 'Asia/Kolkata', day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).format(new Date()) + ' IST';
  const istTime = () => new Intl.DateTimeFormat('en-GB', { timeZone: 'Asia/Kolkata', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).format(new Date());
  function ghErr(status, what) {
    const e = new Error(
      status === 0 ? 'no connection, check the internet' :
      status === 401 ? 'GitHub did not accept the key (wrong, expired or removed). Paste a new one below' :
      (status === 403 || status === 404) ? `the key cannot write to ${what}. It needs arete and arete-site, Contents read and write` :
      (status === 409 || status === 422) ? 'someone else saved at the same moment' :
      `GitHub answered ${status}`);
    e.status = status; e.conflict = status === 409 || status === 422; return e;
  }
  async function gh(method, repo, p, body, accept) {
    let r;
    try {
      r = await fetch(GH + repo + (p ? '/contents/' + p : ''), {
        method, cache: 'no-store',
        headers: Object.assign({ Authorization: 'Bearer ' + store.get(GHKEY), Accept: accept || 'application/vnd.github+json' }, body ? { 'Content-Type': 'application/json' } : {}),
        body: body ? JSON.stringify(body) : undefined,
      });
    } catch (e) { throw ghErr(0, repo); }
    return r;
  }
  async function getFile(repo, p) {
    const r = await gh('GET', repo, p);
    if (r.status === 404) return null;
    if (!r.ok) throw ghErr(r.status, repo);
    const j = await r.json();
    let text;
    if (j.content && j.encoding === 'base64') text = new TextDecoder().decode(b64d(j.content.replace(/\s/g, '')));
    else { // files over 1 MB come without content
      const r2 = await gh('GET', repo, p, null, 'application/vnd.github.raw+json');
      if (!r2.ok) throw ghErr(r2.status, repo);
      text = await r2.text();
    }
    return { sha: j.sha, text };
  }
  async function putFile(repo, p, text, message, sha) {
    const body = { message, content: b64e(new TextEncoder().encode(text)) };
    if (sha) body.sha = sha;
    const r = await gh('PUT', repo, p, body);
    if (!r.ok) throw ghErr(r.status, repo);
    return r.json();
  }
  async function testKey() {
    for (const repo of ['arete', 'arete-site']) { const r = await gh('GET', repo); if (!r.ok) throw ghErr(r.status === 404 ? 403 : r.status, repo); }
  }
  async function saveBody(entry, step) {
    const S = window.AreteShared;
    step('Saving 1 of 2: your records');
    const p = `data/inbox/body-${entry.date}.json`;
    const old = await getFile('arete', p);
    const raw = Object.assign({}, entry, { source: `Arete app, saved ${nowIST()}` });
    await putFile('arete', p, JSON.stringify(raw, null, 2) + '\n', `body: ${entry.date} (app)`, old && old.sha);
    step('Saving 2 of 2: the site');
    for (let attempt = 0; ; attempt++) {
      const cur = await getFile('arete-site', 'data.enc.json');
      if (!cur) throw new Error('the site data file is missing on GitHub');
      const env = JSON.parse(cur.text);
      let pub;
      try { pub = await decrypt(KEY, env); } catch (e) { throw new Error('the passphrase was changed on the computer. Tap Lock, unlock with the new one, then save again'); }
      pub.body = S.bodySummary(S.upsertBody(S.bodyFromSummary(pub.body), entry));
      pub.updated = nowIST();
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, KEY, new TextEncoder().encode(JSON.stringify(pub)));
      const out = { v: 1, alg: 'AES-GCM', kdf: env.kdf, iter: env.iter, salt: env.salt, iv: b64e(iv), ct: b64e(ct) };
      try { await putFile('arete-site', 'data.enc.json', JSON.stringify(out), `body: ${entry.date} (app)`, cur.sha); ENV = out; return pub; }
      catch (e) { if (e.conflict && attempt < 2) continue; throw e; }
    }
  }

  function renderBodyAdd(openDate) {
    const S = window.AreteShared;
    const B = DATA.body;
    const byDate = {}; B.entries.forEach(e => { byDate[e.date] = e; });
    const last = B.entries[B.entries.length - 1] || null;
    const today = istToday();
    const has = k => B.fields.includes(k);
    const lv = k => { for (let i = B.entries.length - 1; i >= 0; i--) if (B.entries[i].v[k] != null) return n1(B.entries[i].v[k]); return ''; };
    const how = k => B.howTo && B.howTo[k] ? `<em>${esc(B.howTo[k])}</em>` : '';
    const inp = k => has(k) ? `<label class="fld"><span>${esc(bl(B, k))} <i>${unitOf(B, k)}</i></span><input id="f_${k}" type="text" inputmode="decimal" autocomplete="off" placeholder="${lv(k) ? 'last ' + lv(k) : ''}">${how(k)}</label>` : '';
    const pairs = S.BODY_PAIRS.filter(([l, r]) => has(l) || has(r));
    const singles = B.fields.filter(k => !pairs.some(p => p.includes(k))); // body.json order (D065)
    const needPass = KEY && KEY.usages && !KEY.usages.includes('encrypt');
    const keySet = !!store.get(GHKEY);
    const startDate = openDate && openDate <= today ? openDate : today;
    $('view').innerHTML =
      phead(byDate[startDate] ? 'Change measurements' : 'Add measurements', 'Leave out anything you did not measure. Weight in kg, the rest in cm.') +
      `<form id="bf" class="bform" autocomplete="off" novalidate>` +
      `<section class="card fcard"><div class="g2">` +
        `<label class="fld"><span>Date</span><input id="f_date" type="date" value="${startDate}" max="${today}"></label>` +
        `<label class="fld"><span>Time <i>IST</i></span><input id="f_time" type="time" value="${byDate[startDate] ? '' : istTime()}"></label></div>` +
        `<label class="fld"><span>Conditions</span><input id="f_cond" type="text" placeholder="e.g. Fasted, after the bathroom"></label>` +
        (last && last.conditions ? `<div class="chips"><button type="button" class="btn sm" id="f_same">Same as last: ${esc(last.conditions)}</button></div>` : '') +
        `<div id="f_exists" class="xnote" hidden></div>` +
      `</section>` +
      `<section class="card fcard"><div class="g2">${singles.map(inp).join('')}</div></section>` +
      `<section class="card fcard">` +
        (has('bicepL') || has('bicepR') ? `<div class="segrow"><span>Biceps measured</span><div class="seg" id="f_bic"><button type="button" data-v="flexed">Flexed</button><button type="button" data-v="relaxed">Relaxed</button></div></div>` : '') +
        pairs.map(([l, r]) => `<div class="g2">${inp(l)}${inp(r)}</div>`).join('') +
      `</section>` +
      `<section class="card fcard"><label class="fld"><span>Note <i>optional</i></span><input id="f_note" type="text"></label></section>` +
      (needPass ? `<section class="card fcard"><label class="fld"><span>Passphrase <i>once on this device, to allow saving</i></span><input id="f_pass" type="password" autocomplete="current-password"></label></section>` : '') +
      `<section class="card fcard"><div class="segrow"><span>GitHub key</span><span class="aside" id="k_st">${keySet ? 'set on this device' : 'not set on this device'}</span></div>` +
        `<div id="k_new" ${keySet ? 'hidden' : ''}><div class="krow"><input id="k_in" type="password" placeholder="Paste the Arete (app) key" autocomplete="off"><button type="button" class="btn" id="k_save">Save key</button></div>` +
        `<div class="hint">Paste it once per device. It stays in this browser only.</div></div>` +
        (keySet ? `<div class="krow"><button type="button" class="btn sm" id="k_change">Change key</button><button type="button" class="btn sm" id="k_del">Remove from this device</button></div>` : '') +
      `</section>` +
      `<div class="savebar"><div class="inner"><div id="f_msg" class="fmsg" role="status"></div>` +
      `<button type="submit" id="f_go" class="btn primary wide">Save</button></div></div>` +
      `</form>`;

    let biceps = null, warned = false, loaded = false;
    const msg = (t, kind) => { const m = $('f_msg'); m.textContent = t; m.className = 'fmsg' + (kind ? ' ' + kind : ''); };
    const reset = () => { if (warned) { warned = false; $('f_go').textContent = 'Save'; } };
    const setBic = v => { biceps = v; document.querySelectorAll('#f_bic button').forEach(b => { b.classList.toggle('on', b.dataset.v === v); b.setAttribute('aria-pressed', b.dataset.v === v); }); };
    document.querySelectorAll('#f_bic button').forEach(b => { b.onclick = () => { setBic(biceps === b.dataset.v ? null : b.dataset.v); reset(); }; });
    if ($('f_same')) $('f_same').onclick = () => { $('f_cond').value = last.conditions; reset(); };
    $('bf').addEventListener('input', reset);
    // A date that already has an entry: load it, saving replaces it. Moving off it clears the form again.
    const loadDate = () => {
      const e = byDate[$('f_date').value];
      $('f_exists').hidden = !e;
      if (!e) {
        if (loaded) {
          loaded = false;
          $('f_time').value = istTime(); $('f_cond').value = ''; $('f_note').value = '';
          B.fields.forEach(k => { if ($('f_' + k)) $('f_' + k).value = ''; });
          setBic(last && last.biceps ? last.biceps : null);
        }
        return;
      }
      loaded = true;
      $('f_exists').textContent = 'This date already has an entry. It is loaded below, and saving replaces it.';
      $('f_time').value = e.time || '';
      $('f_cond').value = e.conditions || '';
      $('f_note').value = e.note || '';
      setBic(e.biceps || null);
      B.fields.forEach(k => { if ($('f_' + k)) $('f_' + k).value = e.v[k] != null ? e.v[k] : ''; });
    };
    $('f_date').onchange = () => { loadDate(); reset(); }; loadDate();
    // New date: biceps starts as last time (visible, tap to change).
    if (!loaded && last && last.biceps) setBic(last.biceps);

    if ($('k_change')) $('k_change').onclick = () => { $('k_new').hidden = false; $('k_in').focus(); };
    if ($('k_del')) $('k_del').onclick = () => { store.del(GHKEY); renderBodyAdd(openDate); };
    $('k_save').onclick = async () => {
      const v = $('k_in').value.trim();
      if (!v) return msg('Paste the key first.', 'bad');
      const prev = store.get(GHKEY);
      store.set(GHKEY, v);
      msg('Checking the key');
      try { await testKey(); $('k_in').value = ''; $('k_new').hidden = true; $('k_st').textContent = 'set on this device'; msg('Key works for arete and arete-site.', 'good'); }
      catch (e) { if (prev) store.set(GHKEY, prev); else store.del(GHKEY); msg('Key not saved: ' + e.message + '.', 'bad'); }
    };

    $('bf').onsubmit = async ev => {
      ev.preventDefault();
      const entry = { date: $('f_date').value };
      const t = $('f_time').value; if (t) entry.time = t.slice(0, 5);
      const c = $('f_cond').value.trim(); if (c) entry.conditions = c;
      if (biceps) entry.biceps = biceps;
      const bad = [];
      for (const k of B.fields) {
        const el = $('f_' + k); if (!el) continue;
        const s = el.value.trim().replace(',', '.');
        if (!s) continue;
        const x = Number(s);
        if (!isFinite(x)) bad.push(`${bl(B, k)} "${el.value}" is not a number`); else entry[k] = x;
      }
      const note = $('f_note').value.trim(); if (note) entry.note = note;
      const chk = S.bodyEntryCheck(B, entry);
      const errors = bad.concat(chk.errors.filter(m => !/must be a number/.test(m)));
      if (S.isDate(entry.date) && entry.date > istToday()) errors.push('The date is in the future');
      if ((entry.bicepL != null || entry.bicepR != null) && !biceps) errors.push('Pick Flexed or Relaxed for the biceps');
      const warnings = chk.warnings.filter(m => !/biceps flexed or relaxed/.test(m));
      if (errors.length) return msg(errors.join('. ') + '.', 'bad');
      if (!store.get(GHKEY)) return msg('Paste the GitHub key first (at the bottom of the form).', 'bad');
      if (warnings.length && !warned) { warned = true; $('f_go').textContent = 'Save anyway'; return msg('Check: ' + warnings.join('. ') + '. Tap Save anyway if it is right.', 'warn'); }
      const go = $('f_go'); go.disabled = true;
      try {
        if (needPass) {
          const pass = $('f_pass').value;
          if (!pass) throw new Error('enter the passphrase once so this device can save');
          const bits = await deriveBits(pass, ENV);
          const k = await aesKey(bits);
          try { await decrypt(k, ENV); } catch (e) { throw new Error('wrong passphrase'); }
          await remember(bits, k); KEY = k;
        }
        const pub = await saveBody(entry, s => msg(s));
        DATA = pub; DATES = Object.keys(DATA.days).sort();
        FLASH = `Saved ${fmtShort(entry.date)}. Other devices show it in about a minute.`;
        location.hash = '#/b';
      } catch (e) {
        msg('Save failed: ' + e.message + '. Try again.', 'bad');
      } finally { go.disabled = false; }
    };
  }

  // ---------- training ----------
  const T = () => DATA.training || { sessions: [], progress: {}, exercises: [] };

  function renderTraining(showAll) {
    const t = T(); const S = t.sessions;
    const from30 = addDays(istToday(), -29);
    const n30 = S.filter(s => s.date >= from30).length;
    const detailed = S.filter(s => s.exercises.length).length;
    const groups = [...new Set(t.exercises.map(x => x.area || 'Other'))];
    const opts = groups.map(g => `<optgroup label="${esc(g)}">` + t.exercises.filter(x => (x.area || 'Other') === g)
      .map(x => `<option value="${esc(x.ex)}">${esc(x.name)} (${x.sessions})</option>`).join('') + '</optgroup>').join('');
    const list = (showAll ? S : S.slice(0, 40)).map(s => `<tr data-go="#/t/s/${s.id}"><td class="item">${esc(s.label || 'Workout')}` +
      `<span class="pl">${fmtLong(s.date)}${s.time ? ', ' + esc(s.time) : ''}</span></td>` +
      `<td>${s.totals.exercises || ''}</td><td>${s.totals.sets || ''}</td><td>${s.totals.volume ? n0(s.totals.volume) : ''}</td></tr>`).join('');
    $('view').innerHTML = phead('Training', S.length ? `Last session ${fmtLong(S[0].date)}` : '') +
      `<section class="card hero"><div class="pills first">${pill('Last 30 days', n30)}${pill('All sessions', S.length)}${pill('With sets', detailed)}</div>` +
      (opts ? `<label class="pick">Progress for one exercise<select id="exsel"><option value="">Choose an exercise</option>${opts}</select></label>` :
        `<div class="cap">Exercise progress appears here once the workout history is imported.</div>`) + `</section>` +
      (S.length ? `<section class="card"><h3><span>Sessions</span><span class="aside">tap one for the sets</span></h3><table class="days"><colgroup><col><col class="c-m"><col class="c-m"><col class="c-k2"></colgroup>` +
      `<thead><tr><th>Session</th><th>Ex</th><th>Sets</th><th>Vol kg</th></tr></thead><tbody>${list}</tbody></table></section>` : `<section class="card hero"><div class="empty">No workouts yet.</div></section>`) +
      (!showAll && S.length > 40 ? `<div class="acts end"><button class="btn sm" id="tall">Show all ${S.length}</button></div>` : '');
    if ($('exsel')) $('exsel').onchange = e => { if (e.target.value) location.hash = '#/t/x/' + encodeURIComponent(e.target.value); };
    if ($('tall')) $('tall').onclick = () => { renderTraining(true); wire(); };
  }

  function renderSession(id) {
    const S = T().sessions; const i = S.findIndex(s => s.id === id); const s = S[i];
    if (!s) { location.replace('#/t'); return; }
    const newer = S[i - 1], older = S[i + 1];
    const cards = s.exercises.map(x => {
      const timed = x.type === 'time';
      let n = 0;
      const hasRpe = x.sets.some(z => z.rpe != null);
      const rows = x.sets.map(st => `<tr class="${st.warmup ? 'wu' : ''}"><td class="item">${st.warmup ? 'Warm-up' : ++n}</td>` +
        (timed ? `<td>${st.secs ?? ''}</td>` : `<td>${st.kg === 0 ? 'BW' : st.kg != null ? n1(st.kg) : st.level != null ? 'L' + n1(st.level) : ''}</td><td>${st.reps ?? ''}</td>`) + (hasRpe ? `<td class="q">${st.rpe ?? ''}</td>` : '') + `</tr>`).join('');
      const sub = x.top && x.top.kg ? `top ${n1(x.top.kg)} × ${x.top.reps}${x.e1rm ? `, e1RM ${n1(x.e1rm)}` : ''}` : x.topLevel ? `top level ${n1(x.topLevel.level)} × ${x.topLevel.reps}` : (k => `${k} set${k === 1 ? '' : 's'}`)(x.sets.filter(z => !z.warmup).length);
      return `<section class="card"><h3><a href="#/t/x/${encodeURIComponent(x.ex)}">${esc(x.name)}</a><span class="aside">${sub}</span></h3>` +
        `<table><colgroup><col>${timed ? '<col class="c-k2">' : '<col class="c-k2"><col class="c-k2">'}${hasRpe ? '<col class="c-m">' : ''}</colgroup>` +
        `<thead><tr><th>Set</th>${timed ? '<th>Secs</th>' : `<th>${x.type === 'level' ? 'Level' : 'kg'}</th><th>Reps</th>`}${hasRpe ? '<th>RPE</th>' : ''}</tr></thead><tbody>${rows}</tbody></table>` +
        (x.sets.some(z => z.note) ? `<div class="xnote">${x.sets.map((z, j) => z.note ? `Set ${j + 1}: ${esc(z.note)}` : '').filter(Boolean).join('. ')}</div>` : '') +
        (x.note ? `<div class="xnote">${esc(x.note)}</div>` : '') + `</section>`;
    }).join('');
    $('view').innerHTML = phead(esc(s.label || 'Workout'), `${fmtLong(s.date)}${s.time ? ', ' + esc(s.time) + ' IST' : ''}`,
        navBtn('l', 'Older session', older ? '#/t/s/' + older.id : '') + navBtn('r', 'Newer session', newer ? '#/t/s/' + newer.id : '')) +
      `<section class="card hero"><div class="pills first">${pill('Exercises', s.totals.exercises)}${pill('Work sets', s.totals.sets)}${pill('Volume', n0(s.totals.volume) + ' kg')}` +
      `${DATA.days[s.date] ? `<a class="pill link" href="#/d/${s.date}">Food that day</a>` : ''}</div>` +
      (s.note ? `<div class="xnote">${esc(s.note)}</div>` : '') + `</section>` +
      (cards || `<section class="card hero"><div class="empty">No exercises recorded for this session${s.source === 'grok' ? ' (the Grok log had the label and time only)' : ''}.</div></section>`);
  }

  function renderExercise(ex) {
    const p = T().progress[ex];
    if (!p) { location.replace('#/t'); return; }
    const pts = p.points;
    const kind = p.type === 'time' ? 'time' : p.type === 'level' ? 'level' : pts.some(x => x.topKg > 0) ? 'weight' : 'reps';
    const best = kind === 'weight' && p.best ? pill('Best set', `${n1(p.best.kg)} × ${p.best.reps}`) : '';
    const be = p.bestE1rm ? pill('Best e1RM', `${n1(p.bestE1rm.value)} kg`) : kind === 'level' && p.bestLevel ? pill('Best', `level ${n1(p.bestLevel.level)} × ${p.bestLevel.reps}`) : '';
    const rows = pts.slice().reverse().map(x => `<tr data-go="#/t/s/${x.sid}"><td class="item">${fmtShort(x.date)} ${x.date.slice(0, 4)}</td>` +
      (kind === 'weight' ? `<td>${x.topKg != null ? n1(x.topKg) + ' × ' + x.topReps : ''}</td><td>${x.e1rm != null ? n1(x.e1rm) : ''}</td>` :
        kind === 'time' ? `<td>${x.maxSecs || ''}</td><td></td>` : kind === 'level' ? `<td>${x.topLevel != null ? 'L' + n1(x.topLevel) + ' × ' + x.topLevelReps : ''}</td><td></td>` : `<td>${x.maxReps || ''}</td><td></td>`) +
      `<td>${x.sets}</td><td>${x.volume ? n0(x.volume) : ''}</td></tr>`).join('');
    const h = kind === 'weight' ? '<th>Top set</th><th>e1RM</th>' : kind === 'time' ? '<th>Best s</th><th></th>' : kind === 'level' ? '<th>Top set</th><th></th>' : '<th>Reps</th><th></th>';
    $('view').innerHTML = phead(esc(p.name), `${p.area ? esc(p.area) + ', ' : ''}${pts.length} session${pts.length > 1 ? 's' : ''}`) +
      `<section class="card hero"><div class="pills first">${best}${be}${pill('First logged', `${fmtShort(pts[0].date)} ${pts[0].date.slice(0, 4)}`)}</div>` +
      (p.loadNote ? `<div class="hint">${esc(p.loadNote)}</div>` : '') +
      (kind === 'weight' ? `<div class="hint">e1RM is an estimated one-rep max from your best set (Epley), so sets with different reps can be compared.</div>` : '') + `</section>` +
      `<section class="card chart"><h3><span>${kind === 'weight' ? 'Top set and e1RM' : kind === 'time' ? 'Longest hold' : kind === 'level' ? 'Top machine level' : 'Most reps in a set'}</span><span class="aside">${kind === 'time' ? 'seconds' : kind === 'weight' ? 'kg, e1RM dashed' : kind === 'level' ? 'level' : 'reps'}</span></h3><div class="cbox"><canvas id="xp"></canvas></div></section>` +
      (kind === 'weight' ? `<section class="card chart"><h3><span>Volume per session</span><span class="aside">kg × reps</span></h3><div class="cbox"><canvas id="xv"></canvas></div></section>` : '') +
      `<section class="card"><h3><span>Sessions</span><span class="aside">tap one for the sets</span></h3><table class="days"><colgroup><col><col class="c-qty2"><col class="c-k2"><col class="c-m"><col class="c-k2"></colgroup>` +
      `<thead><tr><th>Date</th>${h}<th>Sets</th><th>Vol</th></tr></thead><tbody>${rows}</tbody></table></section>`;
    if (!window.Chart) return;
    const labels = pts.map(x => fmtShort(x.date));
    const sc = { x: { grid: { display: false }, border: { display: false }, ticks: { maxRotation: 0, autoSkip: true, autoSkipPadding: 8 } }, y: { grid: { color: COL.grid }, border: { display: false }, grace: '8%', ticks: { maxTicksLimit: 6 } } };
    const click = (e, els) => { if (els.length) location.hash = '#/t/s/' + pts[els[0].index].sid; };
    const main = { borderColor: COL.ink, backgroundColor: COL.ink, borderWidth: 2, pointRadius: 3, tension: .2, cubicInterpolationMode: 'monotone' };
    const ds = kind === 'weight'
      ? [Object.assign({ label: 'Top set kg', data: pts.map(x => x.topKg) }, main),
         { label: 'e1RM', data: pts.map(x => x.e1rm), borderColor: COL.tick, backgroundColor: COL.tick, borderDash: [4, 4], borderWidth: 1.5, pointRadius: 2, tension: .2, cubicInterpolationMode: 'monotone', spanGaps: true }]
      : [Object.assign({ label: kind === 'time' ? 'Seconds' : kind === 'level' ? 'Level' : 'Reps', data: pts.map(x => kind === 'time' ? x.maxSecs : kind === 'level' ? x.topLevel : x.maxReps) }, main)];
    charts.push(new Chart($('xp'), { type: 'line', data: { labels, datasets: ds }, options: { responsive: true, maintainAspectRatio: false, scales: sc, onClick: click,
      interaction: { mode: 'index', intersect: false }, plugins: { tooltip: { displayColors: false, callbacks: { label: c => `${c.dataset.label}: ${n1(c.parsed.y)}` } } } } }));
    if (kind === 'weight') charts.push(new Chart($('xv'), { type: 'bar', data: { labels, datasets: [{ label: 'Volume', data: pts.map(x => x.volume), backgroundColor: COL.bar, borderRadius: 5, maxBarThickness: 22 }] },
      options: { responsive: true, maintainAspectRatio: false, scales: { ...sc, y: { ...sc.y, beginAtZero: true, grace: 0 } }, onClick: click, plugins: { tooltip: { callbacks: { label: c => `${n0(c.parsed.y)} kg` } } } } }));
  }

  // ---------- CSV (D044) ----------
  function download(name, rows) {
    const q = v => { const s = String(v == null ? '' : v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
    const blob = new Blob(['﻿' + rows.map(r => r.map(q).join(',')).join('\r\n')], { type: 'text/csv;charset=utf-8' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name;
    document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 4000);
  }

  function exportCSV(kind, from, to) {
    const days = daysIn(from, to);
    let rows;
    if (kind === 'days') {
      const OM = DATA.settings.optionalMetricsEnabled && DATA.settings.optionalMetrics ? Object.keys(DATA.settings.optionalMetrics) : [];
      rows = [['date', 'weekday', 'kcal', 'protein_g', 'carbs_g', 'fat_g', 'kcal_target', 'protein_min', 'protein_max', 'fast_hrs', 'trained', 'workout', 'workout_time', ...OM]];
      days.forEach(d => rows.push([d.date, d.weekday, n1(d.totals.kcal), n1(d.totals.p), n1(d.totals.c), n1(d.totals.f), d.target && d.target.kcal,
        d.target && d.target.proteinMin, d.target && d.target.proteinMax, d.fast ? d.fast.text.replace(' hrs', '') : '', d.workout.trained ? 'yes' : 'no', d.workout.area || '', d.workout.time || '',
        ...OM.map(k => d.metrics && d.metrics[k] != null ? (Array.isArray(d.metrics[k]) ? d.metrics[k].join('; ') : d.metrics[k]) : '')]));
    } else {
      rows = [['date', 'meal', 'time_ist', 'item', 'qty', 'unit', 'place', 'kcal', 'protein_g', 'carbs_g', 'fat_g', 'estimate']];
      days.forEach(d => d.cards.forEach(c => c.items.forEach(it => rows.push([d.date, c.meal, c.time || '', it.name, it.qty, it.unit, it.place || '',
        n1(it.kcal), n1(it.p), n1(it.c), n1(it.f), it.estimate ? 'yes' : 'no']))));
    }
    download(`arete-${kind}-${from}${from === to ? '' : '-to-' + to}.csv`, rows);
  }

  boot();
})();
