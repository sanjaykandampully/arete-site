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
  let charts = [];
  const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
  const WD = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  // Macro colours: validated categorical slots 1-3 (dark) against the panel surface.
  const COL = { p: '#3987e5', c: '#d95926', f: '#199e70', bar: '#3987e5', target: '#c9c9cf', grid: '#26262b', tick: '#8a8a93', surface: '#141416' };

  const n0 = x => Math.round(x).toLocaleString('en-IN');
  const n1 = x => { const r = Math.round(x * 10) / 10; return Number.isInteger(r) ? String(r) : r.toFixed(1); };
  const esc = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const istToday = () => new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Kolkata' }).format(new Date());
  const addDays = (d, n) => { const x = new Date(d + 'T00:00:00Z'); x.setUTCDate(x.getUTCDate() + n); return x.toISOString().slice(0, 10); };
  const dow = d => (new Date(d + 'T00:00:00Z').getUTCDay() + 6) % 7; // Mon = 0
  const monday = d => addDays(d, -dow(d));
  const fmtShort = d => { const [, m, dd] = d.split('-').map(Number); return `${dd} ${MONTHS[m - 1].slice(0, 3)}`; };
  const fmtHrs = mins => `${Math.floor(mins / 60)}:${String(Math.round(mins % 60)).padStart(2, '0')} hrs`;
  const ABBR = { chest: 'Ch', back: 'Bk', biceps: 'Bi', bicep: 'Bi', shoulders: 'Sh', shoulder: 'Sh', triceps: 'Tri', tricep: 'Tri', legs: 'Legs', core: 'Core', arms: 'Arms' };
  const shortLabel = a => !a ? '' : a.replace(/^Gym\s*\W\s*/, '').split(/\s*[\/,&+]\s*/).map(w => ABBR[w.toLowerCase()] || w).join('·');
  const sep = '<span class="sep"> · </span>';
  const macroLine = t => `${n0(t.kcal)} kcal${sep}P ${n0(t.p)}${sep}C ${n0(t.c)}${sep}F ${n0(t.f)}`;

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
  const aesKey = bits => crypto.subtle.importKey('raw', bits, 'AES-GCM', false, ['decrypt']);
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

  async function boot() {
    store.del('arete.unlock'); // old passcode gate (D037, retired)
    let env;
    try {
      const r = await fetch('data.enc.json?v=' + Date.now(), { cache: 'no-store' });
      if (!r.ok) throw new Error(r.status);
      env = await r.json();
    } catch (e) { document.body.textContent = 'Could not load data.'; return; }
    if (!window.crypto || !crypto.subtle) { document.body.textContent = 'This browser cannot unlock Arete.'; return; }
    const saved = await recall();
    if (saved) { try { return opened(await decrypt(saved, env)); } catch (e) { await forget(); } }
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
        $('pass').value = '';
        opened(d);
      } catch (e) { $('lockMsg').textContent = 'Wrong passphrase'; $('pass').select(); }
      finally { btn.disabled = false; }
    };
  }

  function start() {
    $('app').hidden = false;
    $('lockBtn').onclick = async () => { await forget(); location.hash = ''; location.reload(); };
    $('back').onclick = () => { const r = route(); if (history.length > 1) history.back(); else location.hash = r.date ? '#/m/' + r.date.slice(0, 7) : '#/t'; };
    document.querySelectorAll('#tabs button').forEach(b => { b.onclick = () => go(b.dataset.v); });
    window.addEventListener('hashchange', render);
    if (window.Chart) {
      Chart.defaults.color = COL.tick;
      Chart.defaults.borderColor = COL.grid;
      Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
      Chart.defaults.font.size = 11;
      Chart.defaults.animation = false;
    }
    render();
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

  function route() {
    const h = location.hash.replace(/^#\/?/, '').split('/');
    if (h[0] === 'd' && DATA.days[h[1]]) return { view: 'day', date: h[1] };
    if (h[0] === 'b') return { view: 'body' };
    if (h[0] === 't' && h[1] === 's' && h[2]) return { view: 'session', id: h[2], tab: 'train' };
    if (h[0] === 't' && h[1] === 'x' && h[2]) return { view: 'exercise', ex: decodeURIComponent(h[2]), tab: 'train' };
    if (h[0] === 't') return { view: 'train' };
    if (h[0] === 'm' && /^\d{4}-\d{2}$/.test(h[1])) return { view: 'month', month: h[1] };
    if (h[0] === 'w' && /^\d{4}-\d{2}-\d{2}$/.test(h[1])) return { view: 'week', from: monday(h[1]) };
    if (h[0] === 'r' && /^\d{4}-\d{2}-\d{2}$/.test(h[1]) && /^\d{4}-\d{2}-\d{2}$/.test(h[2])) {
      const [a, b] = [h[1], h[2]].sort(); return { view: 'range', from: a, to: b };
    }
    const t = istToday().slice(0, 7);
    return { view: 'month', month: DATES.some(d => d.startsWith(t)) ? t : lastDate().slice(0, 7) };
  }

  function render() {
    charts.forEach(c => c.destroy()); charts = [];
    const r = route();
    const sub = r.view === 'day' || r.view === 'session' || r.view === 'exercise';
    $('back').style.visibility = sub ? 'visible' : 'hidden';
    $('tabs').hidden = r.view === 'day';
    document.querySelectorAll('#tabs button').forEach(b => b.classList.toggle('on', b.dataset.v === (r.tab || r.view)));
    window.scrollTo(0, 0);
    if (r.view === 'day') renderDay(r.date);
    else if (r.view === 'week') renderPeriod(r.from, addDays(r.from, 6), 'week');
    else if (r.view === 'range') renderPeriod(r.from, r.to, 'range');
    else if (r.view === 'body') renderBody();
    else if (r.view === 'train') renderTraining(false);
    else if (r.view === 'session') renderSession(r.id);
    else if (r.view === 'exercise') renderExercise(r.ex);
    else renderMonth(r.month);
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
      avgFast: fasts.length ? fmtHrs(fasts.reduce((a, b) => a + b, 0) / fasts.length) : 'n/a',
      overKcal: tgt ? days.filter(d => d.totals.kcal > d.target.kcal).length : 0,
      proteinHit: tgt ? days.filter(d => d.totals.p >= d.target.proteinMin).length : 0,
    };
  }

  function summaryHTML(s, from, to) {
    if (!s.n) return '<div class="msum">No logged days in this period.</div>';
    const t = s.tgt;
    return `<div class="summary"><div class="lbl">Daily average · ${s.n} logged day${s.n > 1 ? 's' : ''}</div>` +
      `<div class="macros">${macroLine(s.avg)}</div>` +
      (t ? `<div class="meta"><span>Target <b>${n0(t.kcal)}</b> kcal · P <b>${t.proteinMin} to ${t.proteinMax}</b></span>` +
        `<span>${s.avg.kcal > t.kcal ? '+' : ''}${n0(s.avg.kcal - t.kcal)} kcal vs target</span></div>` : '') +
      `<div class="meta"><span>Over kcal target <b>${s.overKcal}/${s.n}</b></span><span>Protein ≥ ${t ? t.proteinMin : ''} <b>${s.proteinHit}/${s.n}</b></span>` +
      `<span>Trained <b>${s.trained}/${s.n}</b></span><span>Avg fast <b>${s.avgFast}</b></span></div>` +
      `<div class="csv"><button data-csv="days" data-from="${from}" data-to="${to}">Days CSV</button><button data-csv="items" data-from="${from}" data-to="${to}">Items CSV</button></div></div>`;
  }

  function chartsHTML(id) {
    return `<section class="card chart"><h3><span>Calories per day</span><span class="tm">dashed: target</span></h3><div class="cbox"><canvas id="${id}k"></canvas></div></section>` +
      `<section class="card chart"><h3><span>Protein per day</span><span class="tm">dashed: 135 to 150 g</span></h3><div class="cbox"><canvas id="${id}p"></canvas></div></section>` +
      `<section class="card chart"><h3><span>Macro split</span><span class="tm">share of kcal</span></h3><div class="cbox donut"><canvas id="${id}d"></canvas></div></section>`;
  }

  function drawPeriodCharts(id, days, s, labelFn) {
    if (!window.Chart || !days.length) return;
    const labels = days.map(labelFn);
    const t = s.tgt;
    const scales = { x: { grid: { display: false }, ticks: { maxRotation: 0, autoSkip: true, autoSkipPadding: 6 } }, y: { beginAtZero: true, grid: { color: COL.grid }, border: { display: false } } };
    const line = (label, v) => ({ type: 'line', label, data: days.map(() => v), borderColor: COL.target, borderDash: [4, 4], borderWidth: 1.5, pointRadius: 0, pointHitRadius: 0, order: 0 });
    const bars = (label, data) => ({ type: 'bar', label, data, backgroundColor: COL.bar, borderRadius: 4, borderSkipped: 'bottom', maxBarThickness: 22, categoryPercentage: .8, barPercentage: .9, order: 1 });
    const opts = unit => ({ responsive: true, maintainAspectRatio: false, scales, interaction: { mode: 'index', intersect: false },
      plugins: { legend: { display: true, labels: { boxWidth: 10, boxHeight: 10 } }, tooltip: { callbacks: { label: c => `${c.dataset.label}: ${n0(c.parsed.y)} ${unit}` } } },
      onClick: (e, els) => { if (els.length) location.hash = '#/d/' + days[els[0].index].date; } });
    charts.push(new Chart($(id + 'k'), { data: { labels, datasets: [bars('kcal', days.map(d => d.totals.kcal)), ...(t ? [line('Target', t.kcal)] : [])] }, options: opts('kcal') }));
    charts.push(new Chart($(id + 'p'), { data: { labels, datasets: [bars('Protein', days.map(d => d.totals.p)), ...(t ? [line('135 g', t.proteinMin), line('150 g', t.proteinMax)] : [])] }, options: opts('g') }));
    drawDonut(id + 'd', s.avg);
  }

  function drawDonut(canvasId, t) {
    if (!window.Chart) return;
    const k = [t.p * 4, t.c * 4, t.f * 9]; const sum = k.reduce((a, b) => a + b, 0) || 1;
    const pct = k.map(v => Math.round(v / sum * 100));
    charts.push(new Chart($(canvasId), {
      type: 'doughnut',
      data: { labels: [`Protein ${pct[0]}%`, `Carbs ${pct[1]}%`, `Fat ${pct[2]}%`], datasets: [{ data: k.map(Math.round), backgroundColor: [COL.p, COL.c, COL.f], borderColor: COL.surface, borderWidth: 2 }] },
      options: { responsive: true, maintainAspectRatio: false, cutout: '62%', plugins: { legend: { position: 'right', labels: { boxWidth: 10, boxHeight: 10, color: '#ececef', font: { size: 13 } } },
        tooltip: { callbacks: { label: c => `${c.label}: ${n0(c.parsed)} kcal` } } } },
    }));
  }

  function dayTableHTML(days) {
    if (!days.length) return '';
    const rows = days.map(d => `<tr data-d="${d.date}"><td class="item">${d.weekday.slice(0, 3)} ${fmtShort(d.date)}<span class="pl">${d.workout.trained ? esc(shortLabel(d.workout.area) || 'Trained') : 'Rest'}</span></td>` +
      `<td class="${d.target && d.totals.kcal > d.target.kcal ? 'over' : ''}">${n0(d.totals.kcal)}</td><td class="${d.target && d.totals.p < d.target.proteinMin ? 'low' : 'okp'}">${n0(d.totals.p)}</td>` +
      `<td>${n0(d.totals.c)}</td><td>${n0(d.totals.f)}</td><td class="qty">${d.fast ? d.fast.text.replace(' hrs', '') : ''}</td></tr>`).join('');
    return `<section class="card"><h3><span>Days</span><span class="tm">tap a day</span></h3><table class="days"><colgroup><col><col class="c-k2"><col class="c-m"><col class="c-m"><col class="c-m"><col class="c-qty"></colgroup>` +
      `<thead><tr><th>Day</th><th>kcal</th><th>P</th><th>C</th><th>F</th><th>Fast</th></tr></thead><tbody>${rows}</tbody></table></section>`;
  }

  function wirePeriod() {
    $('view').querySelectorAll('tr[data-d]').forEach(tr => { tr.onclick = () => { location.hash = '#/d/' + tr.dataset.d; }; });
    $('view').querySelectorAll('button[data-csv]').forEach(b => { b.onclick = () => exportCSV(b.dataset.csv, b.dataset.from, b.dataset.to); });
  }

  // ---------- pantry strip ----------
  function pantryHTML() {
    if (!DATA.pantry || !DATA.pantry.length) return '';
    const chips = DATA.pantry.filter(p => p.stockG != null).map(p => `<div class="chip${p.low ? ' low' : ''}"><div class="pn">${esc(p.name)}</div>` +
      `<div class="pv">${n0(p.stockG)} g</div><div class="pd">${p.low ? 'LOW · ' : ''}${p.daysLeft != null ? `~${p.daysLeft} days` : 'no recent use'}</div>` +
      `<div class="pa">as of ${fmtShort(p.asOf)}</div></div>`).join('');
    return `<div class="strip" aria-label="Pantry">${chips}</div>`;
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
    let cells = WD.map(w => `<div class="wd">${w}</div>`).join('');
    for (let i = 0; i < lead; i++) cells += '<div class="cell blank"></div>';
    for (let d = 1; d <= nDays; d++) {
      const date = `${m}-${String(d).padStart(2, '0')}`;
      const day = DATA.days[date];
      if (!day) { cells += `<div class="cell nodata${date === today ? ' today' : ''}"><span class="dn">${d}</span></div>`; continue; }
      const t = day.target;
      const kc = t && day.totals.kcal > t.kcal ? 'over' : 'ok';
      const pc = t ? (day.totals.p >= t.proteinMin ? 'ok' : 'low') : '';
      const tr = day.workout.trained ? `<span class="tr">${esc(shortLabel(day.workout.area) || 'Trained')}</span>` : '<span class="tr rest">Rest</span>';
      cells += `<div class="cell${date === today ? ' today' : ''}" data-d="${date}"><span class="dn">${d}</span>` +
        `<span class="k ${kc}">${n0(day.totals.kcal)}</span><span class="p ${pc}">P ${n0(day.totals.p)}</span>${tr}</div>`;
    }
    const days = daysIn(first, last); const s = stats(days);
    $('view').innerHTML = pantryHTML() +
      `<div class="mhead"><button id="pm" ${prevM < minM ? 'disabled' : ''} aria-label="Previous month">&#8249;</button>` +
      `<div class="title">${MONTHS[mo - 1]} ${y}</div><button id="nm" ${nextM > maxM ? 'disabled' : ''} aria-label="Next month">&#8250;</button></div>` +
      `<div class="legend"><span><span class="dot" style="background:var(--over)"></span>kcal over target</span>` +
      `<span><span class="dot" style="background:var(--accent)"></span>protein ≥ 135</span><span><span class="dot" style="background:var(--under)"></span>protein low</span></div>` +
      `<div class="cal">${cells}</div>` + summaryHTML(s, first, last) + chartsHTML('mc') +
      `<div class="foot">Updated ${esc(DATA.updated)}</div>`;
    $('pm').onclick = () => { location.hash = '#/m/' + prevM; };
    $('nm').onclick = () => { location.hash = '#/m/' + nextM; };
    $('view').querySelectorAll('.cell[data-d]').forEach(c => { c.onclick = () => { location.hash = '#/d/' + c.dataset.d; }; });
    wirePeriod();
    drawPeriodCharts('mc', days, s, d => String(Number(d.date.slice(8))));
  }

  function renderPeriod(from, to, kind) {
    const days = daysIn(from, to); const s = stats(days);
    let head;
    if (kind === 'week') {
      const pw = addDays(from, -7), nw = addDays(from, 7);
      head = `<div class="mhead"><button id="pw" ${addDays(from, -1) < DATES[0] ? 'disabled' : ''} aria-label="Previous week">&#8249;</button>` +
        `<div class="title">${fmtShort(from)} to ${fmtShort(to)}<div class="sub">Week (Mon to Sun) · ${from.slice(0, 4)}</div></div>` +
        `<button id="nw" ${nw > lastDate() ? 'disabled' : ''} aria-label="Next week">&#8250;</button></div>`;
      setTimeout(() => { $('pw').onclick = () => { location.hash = '#/w/' + pw; }; $('nw').onclick = () => { location.hash = '#/w/' + nw; }; });
    } else {
      const presets = [[7, '7 days'], [14, '14 days'], [30, '30 days'], [0, 'All']];
      head = `<div class="range"><label>From<input type="date" id="rf" value="${from}" min="${DATES[0]}" max="${lastDate()}"></label>` +
        `<label>To<input type="date" id="rt" value="${to}" min="${DATES[0]}" max="${lastDate()}"></label><button id="ra">Show</button></div>` +
        `<div class="presets">${presets.map(([n, l]) => `<button data-n="${n}">${l}</button>`).join('')}</div>` +
        `<div class="ptitle">${fmtShort(from)} ${from.slice(0, 4)} to ${fmtShort(to)} ${to.slice(0, 4)}</div>`;
      setTimeout(() => {
        $('ra').onclick = () => { if ($('rf').value && $('rt').value) location.hash = `#/r/${$('rf').value}/${$('rt').value}`; };
        $('view').querySelectorAll('.presets button').forEach(b => { b.onclick = () => {
          const n = +b.dataset.n; const t = lastDate(); location.hash = `#/r/${n ? addDays(t, -(n - 1)) : DATES[0]}/${t}`; }; });
      });
    }
    const label = kind === 'week' ? d => d.weekday.slice(0, 3) : d => fmtShort(d.date);
    $('view').innerHTML = head + summaryHTML(s, from, to) + chartsHTML('pc') + dayTableHTML(days);
    wirePeriod();
    drawPeriodCharts('pc', days, s, label);
  }

  // Optional metrics: shown only when switched on in settings.json (D011, D048).
  function metricsHTML(d) {
    const F = DATA.settings.optionalMetrics;
    if (!DATA.settings.optionalMetricsEnabled || !F || !d.metrics) return '';
    const parts = Object.entries(F).filter(([k]) => d.metrics[k] != null).map(([k, f]) =>
      `<span>${esc(f.label)} <b>${Array.isArray(d.metrics[k]) ? esc(d.metrics[k].join(', ')) : (k === 'steps' ? n0(d.metrics[k]) : n1(d.metrics[k]))}${f.unit ? ' ' + esc(f.unit) : ''}</b></span>`);
    return parts.length ? `<div class="meta">${parts.join('')}</div>` : '';
  }

  function renderDay(date) {
    const d = DATA.days[date];
    const i = DATES.indexOf(date);
    const prev = DATES[i - 1], next = DATES[i + 1];
    const [y, mo, dd] = date.split('-').map(Number);
    const t = d.target;
    const w = d.workout.trained ? `<b>${esc(d.workout.area || 'Trained')}</b>${d.workout.time ? ' ' + esc(d.workout.time) : ''}` : 'Rest day';
    const fast = d.fast ? `Fast <b>${esc(d.fast.text)}</b>${d.fast.override ? ' (manual)' : ''}` : 'Fast <b>n/a</b>';
    const flags = d.flags.length ? `<div class="flags">${d.flags.map(f => `<div>${esc(f)}</div>`).join('')}</div>` : '';
    let bars = '';
    if (t) {
      const kp = Math.min(100, d.totals.kcal / t.kcal * 100), pp = Math.min(100, d.totals.p / t.proteinMax * 100);
      const minMark = t.proteinMin / t.proteinMax * 100;
      bars = `<div class="bars"><div class="brow"><span class="bl">kcal</span><div class="track"><div class="fill${d.totals.kcal > t.kcal ? ' overf' : ''}" style="width:${kp}%"></div></div>` +
        `<span class="bv">${n0(d.totals.kcal)} / ${n0(t.kcal)}</span></div>` +
        `<div class="brow"><span class="bl">Protein</span><div class="track"><div class="fill pf" style="width:${pp}%"></div><i class="mark" style="left:${minMark}%"></i></div>` +
        `<span class="bv">${n0(d.totals.p)} / ${t.proteinMin} to ${t.proteinMax}</span></div></div>`;
    }
    const cards = d.cards.map(c => {
      const rows = c.items.map(it => `<tr><td class="item">${esc(it.name)}${it.estimate ? '<span class="est" title="estimate">est</span>' : ''}` +
        `${it.place ? `<span class="pl">${esc(it.place)}</span>` : ''}</td><td class="qty">${n1(it.qty)} ${esc(it.unit)}</td>` +
        `<td>${n0(it.kcal)}</td><td>${n1(it.p)}</td><td>${n1(it.c)}</td><td>${n1(it.f)}</td></tr>`).join('');
      const tot = c.items.length > 1 ? `<tr class="tot"><td class="item">Total</td><td></td><td>${n0(c.totals.kcal)}</td><td>${n1(c.totals.p)}</td><td>${n1(c.totals.c)}</td><td>${n1(c.totals.f)}</td></tr>` : '';
      return `<section class="card"><h3><span>${esc(c.meal)}</span><span class="tm">${c.time ? esc(c.time) + ' IST' : 'whole day'}</span></h3>` +
        `<table><colgroup><col><col class="c-qty"><col class="c-k"><col class="c-m"><col class="c-m"><col class="c-f"></colgroup>` +
        `<thead><tr><th>Item</th><th>Qty</th><th>kcal</th><th>P</th><th>C</th><th>F</th></tr></thead><tbody>${rows}${tot}</tbody></table></section>`;
    }).join('');
    $('view').innerHTML =
      `<div class="dhead"><button id="pd" ${prev ? '' : 'disabled'} aria-label="Previous day">&#8249;</button>` +
      `<div class="title">${d.weekday}, ${dd} ${MONTHS[mo - 1].slice(0, 3)}<div class="sub">${y}</div></div>` +
      `<button id="nd" ${next ? '' : 'disabled'} aria-label="Next day">&#8250;</button></div>` +
      `<div class="summary"><div class="macros">${macroLine(d.totals)}</div>${bars}` +
      `<div class="meta"><span>${fast}</span><span>${w}</span>${(d.sessions || []).map(id => `<a href="#/t/s/${id}">Sets</a>`).join('')}<a href="#/w/${monday(date)}">Week view</a></div>${metricsHTML(d)}${flags}</div>` +
      `<section class="card chart"><h3><span>Macro split</span><span class="tm">share of kcal</span></h3><div class="cbox donut"><canvas id="dd"></canvas></div></section>` +
      cards + `<div class="csv"><button data-csv="items" data-from="${date}" data-to="${date}">Day CSV</button></div>`;
    if (prev) $('pd').onclick = () => { location.hash = '#/d/' + prev; };
    if (next) $('nd').onclick = () => { location.hash = '#/d/' + next; };
    wirePeriod();
    drawDonut('dd', d.totals);
  }

  // ---------- Phase 4: body ----------
  const bl = (B, k) => (B.labels && B.labels[k]) || k;
  const unitOf = (B, k) => k === 'weightKg' ? 'kg' : 'cm';
  const signed = (x, u) => x == null ? '' : `${x > 0 ? '+' : x < 0 ? '−' : '±'}${n1(Math.abs(x))}${u ? ' ' + u : ''}`;

  function renderBody() {
    const B = DATA.body;
    if (!B || !B.entries.length) {
      $('view').innerHTML = `<div class="summary"><div class="lbl">Body</div><div class="empty">No measurements yet.</div>` +
        `<div class="meta">Weekly: weight, and neck, shoulders, chest, biceps, forearms, waist, hips, thighs, calves. Goal ${B && B.goal ? B.goal.weightKg + ' kg' : ''} lean gain.</div></div>`;
      return;
    }
    const E = B.entries, last = E[E.length - 1];
    const w = B.latest.weightKg, w0 = B.first.weightKg;
    const prevW = last.d.weightKg;
    const head = `<div class="summary"><div class="lbl">Latest · ${last.weekday.slice(0, 3)} ${fmtShort(last.date)} ${last.date.slice(0, 4)}${last.conditions ? ' · ' + esc(last.conditions) : ''}</div>` +
      (w ? `<div class="big">${n1(w.value)} <span class="u">kg</span></div>` : '') +
      `<div class="meta">${prevW != null ? `<span>vs last <b>${signed(prevW, 'kg')}</b></span>` : ''}` +
      (w && w0 && w0.date !== w.date ? `<span>since ${fmtShort(w0.date)} <b>${signed(w.value - w0.value, 'kg')}</b></span>` : '') +
      (B.toGoalKg != null ? `<span>to ${B.goal.weightKg} kg <b>${B.toGoalKg > 0 ? n1(B.toGoalKg) + ' kg to go' : 'reached'}</b></span>` : '') +
      (B.latest.waist ? `<span>waist <b>${n1(B.latest.waist.value)} cm</b></span>` : '') + `</div></div>`;
    const pair = `<div class="pair"><section class="card chart"><h3><span>Weight</span><span class="tm">kg</span></h3><div class="cbox sm"><canvas id="bw"></canvas></div></section>` +
      `<section class="card chart"><h3><span>Waist</span><span class="tm">cm</span></h3><div class="cbox sm"><canvas id="bwa"></canvas></div></section></div>`;
    const rows = B.fields.filter(k => B.latest[k]).map(k => {
      const L = B.latest[k], F = B.first[k], u = unitOf(B, k);
      const dPrev = E.slice().reverse().find(e => e.v[k] != null).d[k];
      const dFirst = F.date !== L.date ? L.value - F.value : null;
      return `<tr><td class="item">${esc(bl(B, k))}</td><td>${n1(L.value)}</td><td class="${cls(k, dPrev)}">${signed(dPrev)}</td>` +
        `<td class="${cls(k, dFirst)}">${signed(dFirst)}</td><td class="qty">${u}</td></tr>`;
    }).join('');
    const table = `<section class="card"><h3><span>Measurements</span><span class="tm">change vs last and first</span></h3>` +
      `<table><colgroup><col><col class="c-k2"><col class="c-k2"><col class="c-k2"><col class="c-u"></colgroup>` +
      `<thead><tr><th>Part</th><th>Now</th><th>Last</th><th>First</th><th></th></tr></thead><tbody>${rows}</tbody></table></section>`;
    const hist = `<section class="card"><h3><span>History</span><span class="tm">${E.length} entr${E.length > 1 ? 'ies' : 'y'}</span></h3>` +
      `<table><colgroup><col><col class="c-k2"><col class="c-k2"></colgroup><thead><tr><th>Date</th><th>kg</th><th>Waist</th></tr></thead><tbody>` +
      E.slice().reverse().map(e => `<tr><td class="item">${e.weekday.slice(0, 3)} ${fmtShort(e.date)} ${e.date.slice(0, 4)}${e.conditions ? `<span class="pl">${esc(e.conditions)}</span>` : ''}</td>` +
        `<td>${e.v.weightKg != null ? n1(e.v.weightKg) : ''}</td><td>${e.v.waist != null ? n1(e.v.waist) : ''}</td></tr>`).join('') + `</tbody></table></section>`;
    $('view').innerHTML = head + pair + table + hist + `<div class="csv"><button id="bcsv">Body CSV</button></div>`;
    $('bcsv').onclick = () => {
      const r = [['date', 'time', 'conditions', ...B.fields.map(k => `${k}_${unitOf(B, k)}`), 'note']];
      E.forEach(e => r.push([e.date, e.time || '', e.conditions || '', ...B.fields.map(k => e.v[k] ?? ''), e.note || '']));
      download('arete-body.csv', r);
    };
    // Weight and waist side by side (D021).
    const lineChart = (id, k, extra) => {
      const pts = E.filter(e => e.v[k] != null);
      if (!window.Chart || !pts.length) return;
      charts.push(new Chart($(id), { type: 'line', data: { labels: pts.map(e => fmtShort(e.date)), datasets: [
        { label: bl(B, k), data: pts.map(e => e.v[k]), borderColor: COL.bar, backgroundColor: COL.bar, borderWidth: 2, pointRadius: 3, tension: .25, cubicInterpolationMode: 'monotone' }, ...(extra || [])] },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } },
          scales: { x: { grid: { display: false }, ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 4 } }, y: { grid: { color: COL.grid }, border: { display: false }, grace: '5%' } } } }));
    };
    const wp = E.filter(e => e.v.weightKg != null);
    lineChart('bw', 'weightKg', B.goal ? [{ label: 'Goal', data: wp.map(() => B.goal.weightKg), borderColor: COL.target, borderDash: [4, 4], borderWidth: 1.5, pointRadius: 0 }] : []);
    lineChart('bwa', 'waist');
  }
  // Lean gain: a growing waist is the watch item, a shrinking one is good. The sign is always shown too.
  function cls(k, d) { if (d == null || d === 0) return 'qty'; if (k === 'waist') return d > 0 ? 'over' : 'okp'; return ''; }

  // ---------- Phase 4: training ----------
  const T = () => DATA.training || { sessions: [], progress: {}, exercises: [] };

  function renderTraining(showAll) {
    const t = T(); const S = t.sessions;
    const from30 = addDays(istToday(), -29);
    const n30 = S.filter(s => s.date >= from30).length;
    const detailed = S.filter(s => s.exercises.length).length;
    const groups = [...new Set(t.exercises.map(x => x.area || 'Other'))];
    const opts = groups.map(g => `<optgroup label="${esc(g)}">` + t.exercises.filter(x => (x.area || 'Other') === g)
      .map(x => `<option value="${esc(x.ex)}">${esc(x.name)} (${x.sessions})</option>`).join('') + '</optgroup>').join('');
    const list = (showAll ? S : S.slice(0, 40)).map(s => `<tr data-s="${s.id}"><td class="item">${s.weekday.slice(0, 3)} ${fmtShort(s.date)} ${s.date.slice(2, 4)}` +
      `<span class="pl">${esc(s.label || '')}${s.time ? ' · ' + esc(s.time) : ''}</span></td>` +
      `<td>${s.totals.exercises || ''}</td><td>${s.totals.sets || ''}</td><td>${s.totals.volume ? n0(s.totals.volume) : ''}</td></tr>`).join('');
    $('view').innerHTML = `<div class="summary"><div class="lbl">Training</div>` +
      `<div class="meta"><span>Last 30 days <b>${n30}</b></span><span>All sessions <b>${S.length}</b></span><span>With sets <b>${detailed}</b></span></div>` +
      (opts ? `<label class="pick">Exercise progress<select id="exsel"><option value="">Choose an exercise</option>${opts}</select></label>` :
        `<div class="meta">Exercise progress appears here once the workout history is imported.</div>`) + `</div>` +
      `<section class="card"><h3><span>Sessions</span><span class="tm">tap for sets</span></h3><table class="days"><colgroup><col><col class="c-m"><col class="c-m"><col class="c-k2"></colgroup>` +
      `<thead><tr><th>Session</th><th>Ex</th><th>Sets</th><th>Vol</th></tr></thead><tbody>${list}</tbody></table></section>` +
      (!showAll && S.length > 40 ? `<div class="csv"><button id="tall">Show all ${S.length}</button></div>` : '');
    if ($('exsel')) $('exsel').onchange = e => { if (e.target.value) location.hash = '#/t/x/' + encodeURIComponent(e.target.value); };
    if ($('tall')) $('tall').onclick = () => renderTraining(true);
    $('view').querySelectorAll('tr[data-s]').forEach(tr => { tr.onclick = () => { location.hash = '#/t/s/' + tr.dataset.s; }; });
  }

  function renderSession(id) {
    const S = T().sessions; const i = S.findIndex(s => s.id === id); const s = S[i];
    if (!s) { location.hash = '#/t'; return; }
    const newer = S[i - 1], older = S[i + 1];
    const cards = s.exercises.map(x => {
      const timed = x.type === 'time';
      let n = 0;
      const hasRpe = x.sets.some(z => z.rpe != null);
      const rows = x.sets.map(st => `<tr class="${st.warmup ? 'wu' : ''}"><td class="item">${st.warmup ? 'W' : ++n}</td>` +
        (timed ? `<td>${st.secs ?? ''}</td>` : `<td>${st.kg === 0 ? 'BW' : st.kg != null ? n1(st.kg) : st.level != null ? 'L' + n1(st.level) : ''}</td><td>${st.reps ?? ''}</td>`) + (hasRpe ? `<td class="qty">${st.rpe ?? ''}</td>` : '') + `</tr>`).join('');
      const sub = x.top && x.top.kg ? `top ${n1(x.top.kg)} × ${x.top.reps}${x.e1rm ? ` · e1RM ${n1(x.e1rm)}` : ''}` : x.topLevel ? `top level ${n1(x.topLevel.level)} × ${x.topLevel.reps}` : (k => `${k} set${k === 1 ? '' : 's'}`)(x.sets.filter(z => !z.warmup).length);
      return `<section class="card"><h3><a href="#/t/x/${encodeURIComponent(x.ex)}">${esc(x.name)}</a><span class="tm">${sub}</span></h3>` +
        `<table><colgroup><col>${timed ? '<col class="c-k2">' : '<col class="c-k2"><col class="c-k2">'}${hasRpe ? '<col class="c-m">' : ''}</colgroup>` +
        `<thead><tr><th>Set</th>${timed ? '<th>Secs</th>' : `<th>${x.type === 'level' ? 'Level' : 'kg'}</th><th>Reps</th>`}${hasRpe ? '<th>RPE</th>' : ''}</tr></thead><tbody>${rows}</tbody></table>` +
        (x.sets.some(z => z.note) ? `<div class="xnote">${x.sets.map((z, i) => z.note ? `Set ${i + 1}: ${esc(z.note)}` : '').filter(Boolean).join(' · ')}</div>` : '') +
        (x.note ? `<div class="xnote">${esc(x.note)}</div>` : '') + `</section>`;
    }).join('');
    $('view').innerHTML = `<div class="dhead"><button id="po" ${older ? '' : 'disabled'} aria-label="Older session">&#8249;</button>` +
      `<div class="title">${esc(s.label || 'Workout')}<div class="sub">${s.weekday}, ${fmtShort(s.date)} ${s.date.slice(0, 4)}${s.time ? ' · ' + esc(s.time) + ' IST' : ''}</div></div>` +
      `<button id="pn" ${newer ? '' : 'disabled'} aria-label="Newer session">&#8250;</button></div>` +
      `<div class="summary"><div class="meta"><span>Exercises <b>${s.totals.exercises}</b></span><span>Work sets <b>${s.totals.sets}</b></span>` +
      `<span>Volume <b>${n0(s.totals.volume)} kg</b></span>${DATA.days[s.date] ? `<a href="#/d/${s.date}">Food that day</a>` : ''}</div>` +
      (s.note ? `<div class="xnote">${esc(s.note)}</div>` : '') + `</div>` +
      (cards || `<div class="msum">No exercises recorded for this session${s.source === 'grok' ? ' (the Grok log had the label and time only)' : ''}.</div>`);
    if (older) $('po').onclick = () => { location.hash = '#/t/s/' + older.id; };
    if (newer) $('pn').onclick = () => { location.hash = '#/t/s/' + newer.id; };
  }

  function renderExercise(ex) {
    const p = T().progress[ex];
    if (!p) { location.hash = '#/t'; return; }
    const pts = p.points;
    const kind = p.type === 'time' ? 'time' : p.type === 'level' ? 'level' : pts.some(x => x.topKg > 0) ? 'weight' : 'reps';
    const best = kind === 'weight' && p.best ? `<span>Best set <b>${n1(p.best.kg)} × ${p.best.reps}</b> ${fmtShort(p.best.date)}</span>` : '';
    const be = p.bestE1rm ? `<span>Best e1RM <b>${n1(p.bestE1rm.value)} kg</b></span>` : kind === 'level' && p.bestLevel ? `<span>Best <b>level ${n1(p.bestLevel.level)} × ${p.bestLevel.reps}</b> ${fmtShort(p.bestLevel.date)}</span>` : '';
    const rows = pts.slice().reverse().map(x => `<tr data-s="${x.sid}"><td class="item">${fmtShort(x.date)} ${x.date.slice(2, 4)}</td>` +
      (kind === 'weight' ? `<td>${x.topKg != null ? n1(x.topKg) + ' × ' + x.topReps : ''}</td><td>${x.e1rm != null ? n1(x.e1rm) : ''}</td>` :
        kind === 'time' ? `<td>${x.maxSecs || ''}</td><td></td>` : kind === 'level' ? `<td>${x.topLevel != null ? 'L' + n1(x.topLevel) + ' × ' + x.topLevelReps : ''}</td><td></td>` : `<td>${x.maxReps || ''}</td><td></td>`) +
      `<td>${x.sets}</td><td>${x.volume ? n0(x.volume) : ''}</td></tr>`).join('');
    const h = kind === 'weight' ? '<th>Top set</th><th>e1RM</th>' : kind === 'time' ? '<th>Best s</th><th></th>' : kind === 'level' ? '<th>Top set</th><th></th>' : '<th>Reps</th><th></th>';
    $('view').innerHTML = `<div class="dhead"><span style="width:48px"></span><div class="title">${esc(p.name)}<div class="sub">${esc(p.area || '')}${p.area ? ' · ' : ''}${pts.length} session${pts.length > 1 ? 's' : ''}</div></div><span style="width:48px"></span></div>` +
      `<div class="summary"><div class="meta">${best}${be}<span>First ${fmtShort(pts[0].date)} ${pts[0].date.slice(0, 4)}</span></div>` +
      (p.loadNote ? `<div class="hint">${esc(p.loadNote)}</div>` : '') +
      (kind === 'weight' ? `<div class="hint">e1RM: estimated one-rep max from your best set (Epley), so sets of different reps can be compared.</div>` : '') + `</div>` +
      `<section class="card chart"><h3><span>${kind === 'weight' ? 'Top set and e1RM' : kind === 'time' ? 'Longest hold' : kind === 'level' ? 'Top machine level' : 'Most reps in a set'}</span><span class="tm">${kind === 'time' ? 'seconds' : kind === 'weight' ? 'kg' : kind === 'level' ? 'level' : 'reps'}</span></h3><div class="cbox"><canvas id="xp"></canvas></div></section>` +
      (kind === 'weight' ? `<section class="card chart"><h3><span>Volume per session</span><span class="tm">kg × reps</span></h3><div class="cbox"><canvas id="xv"></canvas></div></section>` : '') +
      `<section class="card"><h3><span>Sessions</span><span class="tm">tap for sets</span></h3><table class="days"><colgroup><col><col class="c-qty2"><col class="c-k2"><col class="c-m"><col class="c-k2"></colgroup>` +
      `<thead><tr><th>Date</th>${h}<th>Sets</th><th>Vol</th></tr></thead><tbody>${rows}</tbody></table></section>`;
    $('view').querySelectorAll('tr[data-s]').forEach(tr => { tr.onclick = () => { location.hash = '#/t/s/' + tr.dataset.s; }; });
    if (!window.Chart) return;
    const labels = pts.map(x => fmtShort(x.date));
    const sc = { x: { grid: { display: false }, ticks: { maxRotation: 0, autoSkip: true, autoSkipPadding: 8 } }, y: { grid: { color: COL.grid }, border: { display: false }, grace: '8%' } };
    const click = (e, els) => { if (els.length) location.hash = '#/t/s/' + pts[els[0].index].sid; };
    const ds = kind === 'weight'
      ? [{ label: 'Top set kg', data: pts.map(x => x.topKg), borderColor: COL.bar, backgroundColor: COL.bar, borderWidth: 2, pointRadius: 3, tension: .2, cubicInterpolationMode: 'monotone' },
         { label: 'e1RM', data: pts.map(x => x.e1rm), borderColor: COL.target, backgroundColor: COL.target, borderDash: [4, 4], borderWidth: 1.5, pointRadius: 2, tension: .2, cubicInterpolationMode: 'monotone', spanGaps: true }]
      : [{ label: kind === 'time' ? 'Seconds' : kind === 'level' ? 'Level' : 'Reps', data: pts.map(x => kind === 'time' ? x.maxSecs : kind === 'level' ? x.topLevel : x.maxReps), borderColor: COL.bar, backgroundColor: COL.bar, borderWidth: 2, pointRadius: 3, tension: .2, cubicInterpolationMode: 'monotone' }];
    charts.push(new Chart($('xp'), { type: 'line', data: { labels, datasets: ds }, options: { responsive: true, maintainAspectRatio: false, scales: sc, onClick: click,
      interaction: { mode: 'index', intersect: false }, plugins: { legend: { display: kind === 'weight', labels: { boxWidth: 10, boxHeight: 10 } } } } }));
    if (kind === 'weight') charts.push(new Chart($('xv'), { type: 'bar', data: { labels, datasets: [{ label: 'Volume', data: pts.map(x => x.volume), backgroundColor: COL.bar, borderRadius: 4, maxBarThickness: 22 }] },
      options: { responsive: true, maintainAspectRatio: false, scales: { ...sc, y: { ...sc.y, beginAtZero: true, grace: 0 } }, onClick: click, plugins: { legend: { display: false } } } }));
  }

  function download(name, rows) {
    const q = v => { const s = String(v == null ? '' : v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
    const blob = new Blob(['﻿' + rows.map(r => r.map(q).join(',')).join('\r\n')], { type: 'text/csv;charset=utf-8' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name;
    document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 4000);
  }

  // ---------- CSV ----------
  function exportCSV(kind, from, to) {
    const days = daysIn(from, to);
    const q = v => { const s = String(v == null ? '' : v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
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
    const csv = rows.map(r => r.map(q).join(',')).join('\r\n');
    const name = `arete-${kind}-${from}${from === to ? '' : '-to-' + to}.csv`;
    const blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 4000);
  }

  boot();
})();
