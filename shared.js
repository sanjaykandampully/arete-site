// Arete shared code: runs in the browser (window.AreteShared) and in Node (require).
// One copy of the body rules, so an entry saved from the phone and a build on the
// computer give exactly the same numbers and checks (D059).
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.AreteShared = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';
  const WD = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
  const round = (x, d = 1) => { const m = 10 ** d; return Math.round((x + Number.EPSILON) * m) / m; };
  const weekday = d => WD[new Date(d + 'T00:00:00Z').getUTCDay()];
  const isDate = d => typeof d === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(d) && !isNaN(Date.parse(d));
  const isTime = t => typeof t === 'string' && /^([01]\d|2[0-3]):[0-5]\d$/.test(t);

  // Limits (D046). The form and validate.js both use these.
  const BODY_RANGE = { weightKg: [35, 160], default: [10, 200] };
  const bodyRange = k => BODY_RANGE[k] || BODY_RANGE.default;
  const BODY_PAIRS = [['bicepL', 'bicepR'], ['forearmL', 'forearmR'], ['thighL', 'thighR'], ['calfL', 'calfR']];
  const BICEPS = ['flexed', 'relaxed'];
  const BODY_META = ['date', 'time', 'conditions', 'biceps', 'note', 'source'];

  // Checks one entry. errors block a save or a build; warnings are shown and can be accepted.
  function bodyEntryCheck(body, e) {
    const errors = [], warnings = [];
    const labels = body.labels || {};
    const L = k => labels[k] || k;
    const known = new Set([...body.fields, ...BODY_META]);
    if (!isDate(e.date)) errors.push('date must be YYYY-MM-DD');
    if (e.time != null && !isTime(e.time)) errors.push('time must be HH:MM');
    for (const k of Object.keys(e)) if (!known.has(k)) errors.push(`unknown field "${k}"`);
    if (!body.fields.some(k => typeof e[k] === 'number')) errors.push('no measurements in this entry');
    for (const k of body.fields) {
      if (e[k] == null) continue;
      if (typeof e[k] !== 'number' || !isFinite(e[k])) { errors.push(`${L(k)} must be a number`); continue; }
      const [lo, hi] = bodyRange(k);
      if (e[k] < lo || e[k] > hi) errors.push(`${L(k)} ${e[k]} looks wrong (expected ${lo} to ${hi})`);
    }
    if (e.biceps != null && !BICEPS.includes(e.biceps)) errors.push('biceps must be flexed or relaxed');
    if (e.biceps == null && (e.bicepL != null || e.bicepR != null)) warnings.push('biceps flexed or relaxed not recorded');
    if (!e.conditions) warnings.push('conditions not recorded (e.g. Sunday morning, before food)');
    for (const [l, r] of BODY_PAIRS)
      if (e[l] && e[r] && Math.abs(e[l] - e[r]) / Math.max(e[l], e[r]) > 0.15) warnings.push(`${L(l)} ${e[l]} and ${L(r)} ${e[r]} differ by more than 15%, check for a typo`);
    return { errors, warnings };
  }

  // Body summary for the site (D046). Input: the body.json object (fields, labels, units, goal, entries).
  function bodySummary(b) {
    const entries = [...b.entries].sort((x, y) => x.date.localeCompare(y.date)).map(e => {
      const v = {};
      for (const k of b.fields) if (typeof e[k] === 'number') v[k] = e[k];
      return { date: e.date, weekday: weekday(e.date), time: e.time || null, conditions: e.conditions || null, biceps: e.biceps || null, note: e.note || null, v };
    });
    // change vs the previous entry that has the same field
    for (let i = 0; i < entries.length; i++) {
      entries[i].d = {};
      for (const k of b.fields) {
        if (entries[i].v[k] == null) continue;
        for (let j = i - 1; j >= 0; j--) if (entries[j].v[k] != null) { entries[i].d[k] = round(entries[i].v[k] - entries[j].v[k], 2); break; }
      }
    }
    const latest = {}, first = {};
    for (const e of entries) for (const k of Object.keys(e.v)) { if (!first[k]) first[k] = { date: e.date, value: e.v[k] }; latest[k] = { date: e.date, value: e.v[k] }; }
    const goal = b.goal || null;
    const w = latest.weightKg;
    return {
      fields: b.fields, labels: b.labels || {}, howTo: b.howTo || {}, units: b.units, goal, entries,
      latest, first,
      toGoalKg: goal && w ? round(goal.weightKg - w.value, 1) : null,
    };
  }

  // Turns a site summary back into body.json-style entries (the browser only has the summary).
  function bodyFromSummary(s) {
    return {
      fields: s.fields, labels: s.labels, howTo: s.howTo, units: s.units, goal: s.goal,
      entries: s.entries.map(e => {
        const r = { date: e.date };
        if (e.time) r.time = e.time;
        if (e.conditions) r.conditions = e.conditions;
        if (e.biceps) r.biceps = e.biceps;
        Object.assign(r, e.v);
        if (e.note) r.note = e.note;
        return r;
      }),
    };
  }

  // Adds or replaces (same date) one entry.
  function upsertBody(body, entry) {
    const entries = body.entries.filter(e => e.date !== entry.date).concat([entry]).sort((a, b) => a.date.localeCompare(b.date));
    return Object.assign({}, body, { entries });
  }

  return { round, weekday, isDate, isTime, BODY_RANGE, bodyRange, BODY_PAIRS, BICEPS, BODY_META, bodyEntryCheck, bodySummary, bodyFromSummary, upsertBody };
});
