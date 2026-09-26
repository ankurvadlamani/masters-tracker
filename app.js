// Masters Journey: research → shortlist → documents → apply → decisions → finance → visa → departure → arrival.
// Public files (no personal data): research.json (programme facts), updates.json (weekly research run), monitor.json (daily page checks).
// Private file: private.enc.json — everything personal, AES-GCM encrypted with a key derived from your password.
'use strict';

// ---------------------------------------------------------------- constants
const REPO = (() => {
  const h = location.hostname;
  if (h.endsWith('.github.io')) {
    const seg = location.pathname.split('/').filter(Boolean)[0];
    return `${h.replace('.github.io', '')}/${seg || h}`;
  }
  return new URLSearchParams(location.search).get('repo') || 'ankurvadlamani/masters-tracker';
})();
const STAGES = [
  ['researching', 'Researching'], ['shortlisted', 'Shortlisted'], ['preparing', 'Preparing'], ['submitted', 'Submitted'],
  ['interview', 'Interview / test'], ['admitted', 'Admitted'], ['accepted', 'Accepted offer'], ['rejected', 'Rejected'], ['withdrawn', 'Withdrawn']
];
const STAGE_LABEL = Object.fromEntries(STAGES);
const STAGE_RANK = Object.fromEntries(STAGES.map(([k], i) => [k, i]));
const BOARD = ['shortlisted', 'preparing', 'submitted', 'interview', 'admitted', 'accepted'];
const DOCS = {
  passport: ['Passport', 'Valid for your whole stay; check the expiry date.'],
  transcripts: ['Transcripts (all semesters)', 'Attested copies; some portals need scans of the originals.'],
  degree: ['Degree / provisional certificate', 'Ask Mahindra University for the provisional certificate.'],
  ielts: ['IELTS TRF', 'Valid 2 years from the test date.'],
  aps: ['APS certificate (India)', 'Required for every German application. Takes weeks.'],
  dmat: ['dMAT certificate (APS India)', 'Needed with APS for German master\'s from summer 2027, unless your APS registration was before 29 Jun 2026. Mark Not needed if exempt.'],
  cv: ['CV (Europass style)', ''],
  sop: ['Statement of purpose', 'Tailor one per programme; track each under Applications.'],
  lor1: ['LOR: Dr Bhargava', ''],
  lor2: ['LOR: Dr Sebastian', ''],
  courses: ['Course descriptions (syllabus)', 'Needed by German and Swedish universities to check credits.'],
  campusfrance: ['Campus France / Études en France file', 'For French programmes.'],
  appfee: ['Application fee paid', 'SEK 900 for Sweden; €100 at some Dutch universities.'],
  funds: ['Proof of funds', 'Blocked account, bank statements or scholarship letter.']
};
const DOC_STATUS = [['not-started', 'Not started'], ['in-progress', 'In progress'], ['ready', 'Ready'], ['na', 'Not needed']];
const docDone = k => ['ready', 'na'].includes(S.priv.documents[k]?.status);
const COUNTRY = { DE: 'Germany', SE: 'Sweden', NL: 'Netherlands', FR: 'France', NO: 'Norway', EU: 'Multi-country' };
const VIEWS = [['dash', 'Dashboard'], ['programs', 'Programs'], ['apps', 'Applications'], ['timeline', 'Timeline'], ['docs', 'Documents'], ['budget', 'Budget'], ['visa', 'Visa & move'], ['settings', 'Settings']];

// ---------------------------------------------------------------- state
const S = { research: null, updates: { runs: [], changes: {} }, monitor: { pages: {} }, priv: null, key: null, salt: null, iter: 600000, view: 'dash', filters: { country: '', stage: '', field: '', q: '', elig: '' }, compare: [], dirty: false, saving: false };

// ---------------------------------------------------------------- helpers
const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const utf8b64 = str => { const bytes = new TextEncoder().encode(str); let bin = ''; for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000)); return btoa(bin); };
const today = () => { const d = new Date(); d.setHours(0, 0, 0, 0); return d; };
const daysTo = iso => iso ? Math.round((new Date(iso + 'T00:00:00') - today()) / 864e5) : null;
const fmtDate = (iso, opt = { day: 'numeric', month: 'short', year: 'numeric' }) => iso ? new Date(iso + 'T00:00:00').toLocaleDateString('en-GB', opt) : '—';
const store = { get: k => { try { return localStorage.getItem(k); } catch { return null; } }, set: (k, v) => { try { localStorage.setItem(k, v); } catch {} }, del: k => { try { localStorage.removeItem(k); sessionStorage.removeItem(k); } catch {} }, sget: k => { try { return sessionStorage.getItem(k); } catch { return null; } }, sset: (k, v) => { try { sessionStorage.setItem(k, v); } catch {} } };
function toast(msg) { const t = $('#toast'); t.textContent = msg; t.classList.add('show'); clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove('show'), 2600); }
function setSync(text, cls = '') { const el = $('#sync'); el.textContent = text; el.className = 'sync ' + cls; }
function getPath(o, p) { return p.split('.').reduce((a, k) => a == null ? a : a[k], o); }
function setPath(o, p, v) { const ks = p.split('.'); let a = o; ks.slice(0, -1).forEach(k => { if (a[k] == null || typeof a[k] !== 'object') a[k] = {}; a = a[k]; }); a[ks.at(-1)] = v; }
const clone = o => JSON.parse(JSON.stringify(o));

// ---------------------------------------------------------------- crypto
async function deriveRaw(pw, salt, iter) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
  return crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' }, base, 256);
}
const importKey = raw => crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
async function decryptBlob(blob, key) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(blob.iv) }, key, unb64(blob.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}
async function encryptBlob(obj, key, salt, iter) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(obj)));
  return { v: 1, kdf: 'PBKDF2-SHA256', iter, salt: b64(salt), iv: b64(iv), ct: b64(ct) };
}

// ---------------------------------------------------------------- data I/O
async function loadPublic(name, fallback) {
  try { const r = await fetch(`${name}?t=${Date.now()}`, { cache: 'no-store' }); if (r.ok) return await r.json(); } catch {}
  return fallback;
}
async function gh(path, opts = {}) {
  const token = S.priv?.github?.token;
  const headers = { Accept: 'application/vnd.github+json' };
  if (token) headers.Authorization = 'Bearer ' + token;
  if (opts.body) headers['Content-Type'] = 'application/json';
  return fetch('https://api.github.com' + path, { ...opts, headers, cache: 'no-store' });
}
async function putFile(name, text, message) {
  if (!S.priv?.github?.token) throw Object.assign(new Error('Connect GitHub in Settings to save changes online.'), { code: 'notoken' });
  const cur = await gh(`/repos/${REPO}/contents/${name}`);
  const sha = cur.ok ? (await cur.json()).sha : undefined;
  const r = await gh(`/repos/${REPO}/contents/${name}`, { method: 'PUT', body: JSON.stringify({ message, content: utf8b64(text), sha }) });
  if (!r.ok) { let m = 'GitHub ' + r.status; try { m += ': ' + (await r.json()).message; } catch {} throw new Error(m); }
}
let saveTimer = null, pending = new Set();
function queueSave(what = 'private', msg = 'Update tracker') {
  pending.add(what); S.dirty = true; setSync('Unsaved changes…');
  clearTimeout(saveTimer); saveTimer = setTimeout(() => flush(msg), 900);
}
async function flush(msg) {
  if (S.saving) { saveTimer = setTimeout(() => flush(msg), 600); return; }
  S.saving = true; setSync('Saving…');
  try {
    if (pending.has('private')) await putFile('private.enc.json', JSON.stringify(await encryptBlob(S.priv, S.key, S.salt, S.iter)), 'Update private tracker data');
    if (pending.has('research')) { S.research.updated = new Date().toISOString().slice(0, 10); await putFile('research.json', JSON.stringify(S.research), msg); }
    pending.clear(); S.dirty = false; setSync('All changes saved', 'ok');
  } catch (e) {
    setSync(e.code === 'notoken' ? 'Not saved: connect GitHub in Settings' : 'Save failed: ' + e.message, 'err');
  } finally { S.saving = false; }
}
window.addEventListener('beforeunload', e => { if (S.dirty) { e.preventDefault(); e.returnValue = ''; } });

// ---------------------------------------------------------------- derived data
function programs() {
  const custom = S.priv?.custom || [];
  const found = (S.updates.add || []).filter(a => !S.research.programs.some(p => p.id === a.id));
  return [...S.research.programs, ...found, ...custom].map(p => {
    const u = S.updates.changes?.[p.id];
    const m = clone(p);
    if (u?.set) Object.entries(u.set).forEach(([k, v]) => setPath(m, k, v));
    if (u?.verified) m.lastVerified = u.verified;
    m._updates = u || null;
    m._app = app(p.id);
    m._custom = custom.includes(p);
    m._found = found.includes(p);
    return m;
  });
}
function app(id) { S.priv.apps[id] ||= { stage: 'researching', notes: '', sop: 'not-started' }; return S.priv.apps[id]; }
const active = p => !['rejected', 'withdrawn'].includes(p._app.stage);
const shortlisted = p => STAGE_RANK[p._app.stage] >= 1 && active(p);
function rateOf(cur) { return (S.research.rates || {})[cur] ?? 1; }
function tuitionPerYearEUR(p) {
  const t = p.tuition; if (!t || t.amount == null) return null;
  const perYear = t.per === 'total' ? t.amount / 2 : t.per === 'semester' ? t.amount * 2 : t.amount;
  return Math.round(perYear * rateOf(t.currency));
}
function livingPerYearEUR(p) { const c = S.research.countries[p.country]; return c ? Math.round(c.livingMonthly * 12 * rateOf(c.currency)) : null; }
const eur = n => n == null ? '—' : '€' + Math.round(n).toLocaleString('en-GB');
function inr(n) { const r = S.priv.profile.inrPerEur; return n == null || !r ? '' : '₹' + Math.round(n * r).toLocaleString('en-IN'); }
function eligibility(p) {
  const pr = S.priv.profile, r = p.requirements || {}, items = [];
  const pct = pr.gpa / pr.gpaScale * 100;
  if (r.gpaPct) items.push(pct >= r.gpaPct ? ['ok', `GPA ${pct.toFixed(1)}% ≥ ${r.gpaPct}%`] : pct >= r.gpaPct - 3 ? ['warn', `GPA ${pct.toFixed(1)}% just under ${r.gpaPct}%`] : ['bad', `GPA ${pct.toFixed(1)}% below ${r.gpaPct}%`]);
  if (r.ielts) items.push(pr.ielts >= r.ielts ? ['ok', `IELTS ${pr.ielts} ≥ ${r.ielts}`] : ['bad', `IELTS ${pr.ielts} below ${r.ielts}`]);
  if (r.ieltsSection) { const lo = Math.min(...Object.values(pr.ieltsSections)); items.push(lo >= r.ieltsSection ? ['ok', `All IELTS sections ≥ ${r.ieltsSection}`] : ['bad', `An IELTS section is below ${r.ieltsSection}`]); }
  (r.prereqs || []).forEach(x => items.push(['warn', `Check prerequisite: ${x}`]));
  if (p.country === 'DE') items.push(S.priv.documents.aps?.status === 'ready' ? ['ok', 'APS certificate ready'] : ['warn', 'APS certificate needed']);
  const ielDate = pr.ieltsDate ? new Date(pr.ieltsDate) : null;
  if (ielDate && p.dates?.deadline) { const exp = new Date(ielDate); exp.setFullYear(exp.getFullYear() + 2); if (new Date(p.dates.deadline) > exp) items.push(['bad', 'IELTS expires before the deadline']); }
  const level = items.some(i => i[0] === 'bad') ? 'bad' : items.some(i => i[0] === 'warn') ? 'warn' : 'ok';
  return { level, items, label: { ok: 'Eligible', warn: 'Check', bad: 'Gap' }[level] };
}
function readiness(p) {
  const keys = p.docs || [];
  if (!keys.length) return 0;
  const done = keys.filter(k => k === 'sop' ? p._app.sop === 'ready' : docDone(k)).length;
  return Math.round(done / keys.length * 100);
}
function events() {
  const ev = [];
  const LBL = { opens: 'Applications open', deadline: 'Application deadline', docs: 'Documents due', results: 'Results', scholarship: 'Scholarship deadline', start: 'Programme starts' };
  programs().filter(active).forEach(p => Object.entries(p.dates || {}).forEach(([k, d]) => d && ev.push({ date: d, kind: k, label: LBL[k] || k, p })));
  (S.priv.milestones || []).forEach(m => ev.push({ date: m.date, kind: 'personal', label: m.title, personal: m }));
  Object.entries(S.priv.documents).forEach(([k, d]) => d.expiry && ev.push({ date: d.expiry, kind: 'expiry', label: `${DOCS[k]?.[0] || k} expires` }));
  return ev.sort((a, b) => a.date.localeCompare(b.date));
}
function monitorFor(p) {
  return (p.watch || []).map(u => ({ url: u, ...(S.monitor.pages?.[u] || {}) }));
}
function alerts() {
  const out = [], dismissed = S.priv.dismissed || {};
  programs().filter(active).forEach(p => {
    monitorFor(p).forEach(m => {
      if (m.lastChanged && m.lastChanged.slice(0, 10) >= (p.lastVerified || '') && !dismissed['mon:' + m.url + m.lastChanged]) out.push({ id: 'mon:' + m.url + m.lastChanged, cls: 'warn', title: `${p.uni}: official page changed`, text: `Changed on ${fmtDate(m.lastChanged.slice(0, 10))}. ${m.newDates?.length ? 'New dates spotted: ' + m.newDates.slice(0, 2).join(' · ') : 'Review the page for new dates or requirements.'}`, p });
    });
    const d = daysTo(p.dates?.deadline);
    if (shortlisted(p) && d != null && d >= 0 && d <= 21 && STAGE_RANK[p._app.stage] < 3) out.push({ id: 'dl:' + p.id + p.dates.deadline, cls: 'hot', title: `${p.uni} closes in ${d} days`, text: `Documents ${readiness(p)}% ready.`, p });
    if (p._updates?.log?.length) { const last = p._updates.log.at(-1); if (daysTo(last.date) >= -14 && !dismissed['upd:' + p.id + last.date]) out.push({ id: 'upd:' + p.id + last.date, cls: 'info', title: `Research update: ${p.uni}`, text: last.text, p }); }
  });
  if (programs().some(p => p.country === 'DE' && shortlisted(p)) && S.priv.documents.aps?.status !== 'ready') out.push({ id: 'aps', cls: 'warn', title: 'APS certificate not ready', text: 'You have German programmes shortlisted. APS takes several weeks, so start now.' });
  Object.entries(S.priv.documents).forEach(([k, d]) => { const n = daysTo(d.expiry); if (n != null && n < 240) out.push({ id: 'exp:' + k, cls: n < 60 ? 'hot' : 'warn', title: `${DOCS[k]?.[0] || k} ${n < 0 ? 'has expired' : 'expires in ' + n + ' days'}`, text: fmtDate(d.expiry) }); });
  return out.filter(a => !dismissed[a.id]);
}

// ---------------------------------------------------------------- UI bits
const pill = (cls, t) => `<span class="pill p-${cls}">${esc(t)}</span>`;
const eligPill = e => pill(e.level === 'ok' ? 'ok' : e.level === 'warn' ? 'warn' : 'bad', e.label);
function daysBadge(iso, kind = 'deadline') {
  const n = daysTo(iso); if (n == null) return '<span class="days muted">—</span>';
  if (kind === 'opens') return n <= 0 ? '<span class="days" style="color:var(--signal)">open now</span>' : `<span class="days">in ${n}d</span>`;
  if (n < 0) return '<span class="days muted">passed</span>';
  return `<span class="days ${n <= 14 ? 'hot' : n <= 45 ? 'warm' : ''}">${n}d</span>`;
}
const stageSelect = p => `<select class="inp" data-stage="${esc(p.id)}" onclick="event.stopPropagation()">${STAGES.map(([k, l]) => `<option value="${k}" ${k === p._app.stage ? 'selected' : ''}>${l}</option>`).join('')}</select>`;
const meter = pct => `<div class="meter" title="${pct}% of documents ready"><i style="width:${pct}%"></i></div>`;

// ---------------------------------------------------------------- views
const V = {};

V.dash = () => {
  const ps = programs(), sl = ps.filter(shortlisted);
  const docKeys = Object.keys(DOCS).filter(k => ps.some(p => shortlisted(p) && (p.docs || []).includes(k)));
  const docsPct = docKeys.length ? Math.round(docKeys.filter(k => docDone(k)).length / docKeys.length * 100) : 0;
  const submitted = sl.filter(p => STAGE_RANK[p._app.stage] >= 3).length;
  const admitted = ps.filter(p => ['admitted', 'accepted'].includes(p._app.stage)).length;
  const accepted = ps.find(p => p._app.stage === 'accepted');
  const visaSteps = accepted ? S.research.countries[accepted.country]?.steps || [] : [];
  const vs = accepted ? (S.priv.visa[accepted.country] || {}) : {};
  const phase = w => visaSteps.filter(s => s[2].startsWith(w));
  const pctOf = arr => arr.length ? Math.round(arr.filter(s => vs[s[0]]).length / arr.length * 100) : 0;
  const steps = [
    ['Research', `${ps.length} programmes`, Math.min(100, ps.length * 10)],
    ['Shortlist', `${sl.length} shortlisted`, Math.min(100, sl.length * 15)],
    ['Documents', `${docsPct}% ready`, docsPct],
    ['Apply', `${submitted}/${sl.length || 0} submitted`, sl.length ? Math.round(submitted / sl.length * 100) : 0],
    ['Decisions', `${admitted} admit${admitted === 1 ? '' : 's'}`, admitted ? 100 : 0],
    ['Finance', S.priv.documents.funds?.status === 'ready' ? 'Funds ready' : 'Plan funds', { 'not-started': 0, 'in-progress': 50, ready: 100, na: 100 }[S.priv.documents.funds?.status || 'not-started']],
    ['Visa', accepted ? `${pctOf(visaSteps.filter(s => !s[2].startsWith('After arrival')))}%` : 'After an offer', accepted ? pctOf(visaSteps.filter(s => !s[2].startsWith('After arrival'))) : 0],
    ['Departure', accepted ? 'Housing, flights' : '—', accepted ? pctOf(visaSteps.filter(s => /housing|flight/i.test(s[0]))) : 0],
    ['Arrival', accepted ? `${pctOf(phase('After arrival'))}%` : '—', accepted ? pctOf(phase('After arrival')) : 0]
  ];
  const curIdx = steps.findIndex(s => s[2] < 100);
  const upcoming = ps.filter(p => shortlisted(p) && daysTo(p.dates?.deadline) >= 0).sort((a, b) => a.dates.deadline.localeCompare(b.dates.deadline)).slice(0, 6);
  const al = alerts();
  return `
  <div class="vh"><div><p class="eyebrow">Your journey</p><h1>Hi ${esc(S.priv.profile.name.split(' ')[0])}, here's where things stand.</h1></div>
  <div class="row"><button class="btn btn-line btn-sm" data-go="programs">Browse programmes</button><button class="btn btn-copper btn-sm" data-ics>Add deadlines to calendar</button></div></div>
  <div class="panel dark"><h2>Journey</h2><div class="steps">${steps.map((s, i) => `<div class="step ${s[2] >= 100 ? 'done' : ''} ${i === curIdx ? 'cur' : ''}"><span class="no">0${i + 1}</span><b>${s[0]}</b><small>${esc(s[1])}</small><div class="bar"><i style="width:${s[2]}%"></i></div></div>`).join('')}</div></div>
  <div class="kpis">
    <div class="kpi"><strong>${sl.length}</strong><span>Shortlisted</span></div>
    <div class="kpi"><strong>${submitted}</strong><span>Submitted</span></div>
    <div class="kpi"><strong>${admitted}</strong><span>Admits</span></div>
    <div class="kpi"><strong>${upcoming[0] ? daysTo(upcoming[0].dates.deadline) + 'd' : '—'}</strong><span>${upcoming[0] ? 'to ' + esc(upcoming[0].uni.split(/[(–]/)[0].trim()) : 'No deadlines'}</span></div>
  </div>
  <div class="g2">
    <div class="panel"><h2>Next deadlines</h2>${upcoming.length ? `<ul class="list">${upcoming.map(p => `<li class="clickable" data-open="${esc(p.id)}"><span class="days ${daysTo(p.dates.deadline) <= 14 ? 'hot' : ''}">${daysTo(p.dates.deadline)}d</span><div class="grow"><div class="t">${esc(p.uni)}</div><div class="s">${esc(p.program)} · ${fmtDate(p.dates.deadline)}</div>${meter(readiness(p))}</div>${eligPill(eligibility(p))}</li>`).join('')}</ul>` : '<div class="empty2">Shortlist programmes to see their deadlines here.</div>'}</div>
    <div class="stack">
      <div class="panel"><h2>Alerts</h2>${al.length ? al.slice(0, 8).map(a => `<div class="alert ${a.cls}"><div ${a.p ? `class="clickable" data-open="${esc(a.p.id)}"` : ''}><b>${esc(a.title)}</b>${esc(a.text)}</div><button class="x3" data-dismiss="${esc(a.id)}" title="Dismiss">✕</button></div>`).join('') : '<div class="muted small">Nothing needs attention right now.</div>'}</div>
      <div class="panel"><h2>Automation</h2>${automationHTML()}</div>
    </div>
  </div>`;
};

function automationHTML() {
  const lastRun = S.updates.runs?.at(-1);
  const mon = S.monitor.lastRun;
  const pages = Object.values(S.monitor.pages || {});
  return `<ul class="list">
    <li><div class="grow"><div class="t">Daily page monitor</div><div class="s">GitHub checks every official programme page each morning and flags changes.</div></div>${mon ? pill('ok', 'Ran ' + fmtDate(mon.slice(0, 10), { day: 'numeric', month: 'short' })) : pill('mute', 'First run pending')}</li>
    <li><div class="grow"><div class="t">Weekly research run</div><div class="s">Claude re-checks deadlines, requirements and fees every week and writes updates here.</div></div>${lastRun ? pill('ok', fmtDate(lastRun.date, { day: 'numeric', month: 'short' })) : pill('mute', 'Not run yet')}</li>
  </ul>${pages.length ? `<p class="small muted" style="margin:10px 0 0">${pages.filter(p => p.status === 'ok').length}/${pages.length} pages reachable in the last check.</p>` : ''}${lastRun?.summary ? `<p class="small" style="margin:10px 0 0">${esc(lastRun.summary)}</p>` : ''}`;
}

V.programs = () => {
  const f = S.filters, all = programs();
  let ps = all.filter(p => (!f.country || p.country === f.country) && (!f.stage || p._app.stage === f.stage) && (!f.field || (p.fields || []).includes(f.field)) && (!f.elig || eligibility(p).level === f.elig) && (!f.q || `${p.uni} ${p.program} ${p.city}`.toLowerCase().includes(f.q.toLowerCase())));
  ps.sort((a, b) => (a.dates?.deadline || '9999').localeCompare(b.dates?.deadline || '9999'));
  const countries = [...new Set(all.map(p => p.country))];
  const fields = [...new Set(all.flatMap(p => p.fields || []))];
  return `
  <div class="vh"><div><p class="eyebrow">Discover</p><h1>Programmes</h1><p>Every programme checked against your profile: GPA ${S.priv.profile.gpa}/${S.priv.profile.gpaScale}, IELTS ${S.priv.profile.ielts}.</p></div>
  <div class="row">${S.compare.length ? `<button class="btn btn-ink btn-sm" data-compare>Compare ${S.compare.length}</button>` : ''}<button class="btn btn-copper btn-sm" data-add>+ Add programme</button></div></div>
  <div class="row" style="margin-bottom:12px"><input class="inp" id="q" placeholder="Search university, programme, city" value="${esc(f.q)}" style="flex:1 1 220px">
    <select class="inp" data-f="field"><option value="">All fields</option>${fields.map(x => `<option ${f.field === x ? 'selected' : ''}>${x}</option>`).join('')}</select>
    <select class="inp" data-f="stage"><option value="">All stages</option>${STAGES.map(([k, l]) => `<option value="${k}" ${f.stage === k ? 'selected' : ''}>${l}</option>`).join('')}</select>
    <select class="inp" data-f="elig"><option value="">Any eligibility</option><option value="ok" ${f.elig === 'ok' ? 'selected' : ''}>Eligible</option><option value="warn" ${f.elig === 'warn' ? 'selected' : ''}>Check</option><option value="bad" ${f.elig === 'bad' ? 'selected' : ''}>Gap</option></select></div>
  <div class="chips" style="margin-bottom:18px"><button class="chip ${!f.country ? 'on' : ''}" data-country="">All ${all.length}</button>${countries.map(c => `<button class="chip ${f.country === c ? 'on' : ''}" data-country="${c}">${COUNTRY[c] || c} ${all.filter(p => p.country === c).length}</button>`).join('')}</div>
  <div class="pcards">${ps.map(p => { const e = eligibility(p); return `
    <div class="pc" data-open="${esc(p.id)}">
      <div class="uni"><span class="cc">${p.country}</span><span style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(p.uni)}</span>${daysBadge(p.dates?.deadline)}</div>
      <h3>${esc(p.program)}</h3>
      <div class="row">${eligPill(e)}${p.verify ? pill('mute', 'verify') : ''}${p._found ? pill('cu', 'new find') : p._updates?.log?.length ? pill('cu', 'updated') : ''}</div>
      <div class="meta"><span>Intake</span><span>${esc(p.intake)}</span><span>Deadline</span><span>${fmtDate(p.dates?.deadline)}</span><span>Tuition/yr</span><span>${eur(tuitionPerYearEUR(p))}</span></div>
      <div class="foot">${stageSelect(p)}<label class="cmp" onclick="event.stopPropagation()"><input type="checkbox" data-cmp="${esc(p.id)}" ${S.compare.includes(p.id) ? 'checked' : ''}>compare</label></div>
    </div>`; }).join('') || '<div class="empty2">No programmes match.</div>'}</div>`;
};

V.apps = () => {
  const ps = programs();
  const out = ps.filter(p => ['rejected', 'withdrawn'].includes(p._app.stage));
  return `
  <div class="vh"><div><p class="eyebrow">Apply</p><h1>Applications</h1><p>Move each programme along as you go. Documents and your SOP are tracked per programme.</p></div></div>
  <div class="kanban">${BOARD.map(st => { const col = ps.filter(p => p._app.stage === st); return `
    <div class="col"><h3>${STAGE_LABEL[st]}<span>${col.length}</span></h3>${col.map(p => `
      <div class="kc" data-open="${esc(p.id)}"><b>${esc(p.uni)}</b><small>${esc(p.program)}</small>${meter(readiness(p))}
        <div class="row"><small>${p.dates?.deadline ? fmtDate(p.dates.deadline, { day: 'numeric', month: 'short' }) : 'no date'}</small>
        <span class="mv" onclick="event.stopPropagation()"><button data-move="${esc(p.id)}" data-dir="-1" title="Back">◀</button><button data-move="${esc(p.id)}" data-dir="1" title="Forward">▶</button></span></div></div>`).join('') || '<small class="muted">—</small>'}</div>`; }).join('')}</div>
  <p class="small muted">Still researching: ${ps.filter(p => p._app.stage === 'researching').length} · Closed: ${out.length} ${out.length ? '(' + out.map(p => esc(p.uni)).join(', ') + ')' : ''}</p>`;
};

V.timeline = () => {
  const ev = events(); const groups = {};
  ev.forEach(e => { const k = e.date.slice(0, 7); (groups[k] ||= []).push(e); });
  return `
  <div class="vh"><div><p class="eyebrow">Plan</p><h1>Timeline</h1><p>Every date from your active programmes, document expiries and your own milestones.</p></div>
  <div class="row"><button class="btn btn-line btn-sm" data-milestone>+ Add milestone</button><button class="btn btn-copper btn-sm" data-ics>Download calendar (.ics)</button></div></div>
  ${Object.entries(groups).map(([m, list]) => `<div class="month"><h3>${new Date(m + '-01T00:00:00').toLocaleDateString('en-GB', { month: 'long', year: 'numeric' })}</h3>${list.map(e => `
    <div class="ev ${daysTo(e.date) < 0 ? 'past' : ''} ${e.p ? 'clickable' : ''}" ${e.p ? `data-open="${esc(e.p.id)}"` : ''}><div class="d">${new Date(e.date + 'T00:00:00').getDate()}<small>${new Date(e.date + 'T00:00:00').toLocaleDateString('en-GB', { weekday: 'short' })}</small></div>
    <div><div class="t" style="font-weight:600">${esc(e.label)}</div><div class="small muted">${e.p ? esc(e.p.uni + ' · ' + e.p.program) : e.kind === 'personal' ? 'Personal milestone' : 'Document'}</div></div>
    <div class="row">${daysBadge(e.date)}${e.personal ? `<button class="x3" data-delms="${esc(e.personal.id)}" title="Remove" style="background:none;border:0;cursor:pointer">✕</button>` : ''}</div></div>`).join('')}</div>`).join('') || '<div class="empty2">No dates yet.</div>'}`;
};

V.docs = () => {
  const ps = programs().filter(shortlisted);
  return `
  <div class="vh"><div><p class="eyebrow">Prepare</p><h1>Documents</h1><p>One status per document. Every programme's checklist updates from here automatically.</p></div></div>
  <div class="tw"><table class="t"><thead><tr><th>Document</th><th>Status</th><th>Expiry</th><th>Needed by</th></tr></thead><tbody>${Object.entries(DOCS).map(([k, [label, hint]]) => { const d = S.priv.documents[k] ||= { status: 'not-started' }; const need = ps.filter(p => (p.docs || []).includes(k)); return `
    <tr><td><b>${esc(label)}</b>${hint ? `<div class="small muted">${esc(hint)}</div>` : ''}</td>
    <td><select class="inp" data-doc="${k}">${DOC_STATUS.map(([v, l]) => `<option value="${v}" ${d.status === v ? 'selected' : ''}>${l}</option>`).join('')}</select></td>
    <td>${['passport', 'ielts', 'aps'].includes(k) ? `<input type="date" class="inp" data-exp="${k}" value="${esc(d.expiry || '')}">` : '<span class="muted">—</span>'}</td>
    <td class="small">${need.length ? need.map(p => esc(p.uni.split(/[(–]/)[0].trim())).join(', ') : '<span class="muted">No shortlisted programme</span>'}</td></tr>`; }).join('')}</tbody></table></div>`;
};

V.budget = () => {
  const ps = programs().filter(active).map(p => ({ p, t: tuitionPerYearEUR(p), l: livingPerYearEUR(p), fee: p.appFee?.amount ? Math.round(p.appFee.amount * rateOf(p.appFee.currency)) : 0 }))
    .map(x => ({ ...x, total: x.t == null ? null : x.t + (x.l || 0) + x.fee })).sort((a, b) => (a.total ?? 1e9) - (b.total ?? 1e9));
  const hasInr = !!S.priv.profile.inrPerEur;
  return `
  <div class="vh"><div><p class="eyebrow">Finance</p><h1>Budget</h1><p>First-year cost: tuition + living at the visa's minimum proof of funds + application fee. Other currencies are converted with the approximate rates in Settings.</p></div></div>
  <div class="tw"><table class="t"><thead><tr><th>Programme</th><th class="num">Tuition / yr</th><th class="num">Living / yr</th><th class="num">App fee</th><th class="num">First year</th>${hasInr ? '<th class="num">In ₹</th>' : ''}</tr></thead><tbody>${ps.map(x => `
    <tr class="clickable" data-open="${esc(x.p.id)}"><td><b>${esc(x.p.uni)}</b><div class="small muted">${esc(x.p.program)}</div>${x.p.tuition?.note ? `<div class="small muted">${esc(x.p.tuition.note)}</div>` : ''}</td>
    <td class="num">${eur(x.t)}</td><td class="num">${eur(x.l)}</td><td class="num">${x.fee ? eur(x.fee) : '—'}</td><td class="num"><b>${eur(x.total)}</b></td>${hasInr ? `<td class="num">${inr(x.total)}</td>` : ''}</tr>`).join('')}</tbody></table></div>
  <div class="g2" style="margin-top:18px">
    <div class="panel"><h2>Proof of funds by country</h2><ul class="list">${Object.entries(S.research.countries).map(([k, c]) => `<li><span class="pill p-ink">${k}</span><div class="grow"><div class="t">${esc(c.name)}</div><div class="s">${esc(c.proof)}</div></div></li>`).join('')}</ul></div>
    <div class="panel"><h2>Scholarships</h2><ul class="list">${S.research.scholarships.map(s => `<li><span class="pill p-ink">${s.country}</span><div class="grow"><div class="t"><a href="${esc(s.link)}" target="_blank" rel="noopener">${esc(s.name)}</a></div><div class="s">${esc(s.covers)} · ${esc(s.window)}</div></div>${s.verify ? pill('mute', 'verify') : ''}</li>`).join('')}</ul></div>
  </div>`;
};

V.visa = () => {
  const ps = programs();
  const acc = ps.filter(p => ['admitted', 'accepted'].includes(p._app.stage)).map(p => p.country);
  const list = acc.length ? [...new Set(acc)] : Object.keys(S.research.countries);
  S.visaTab = list.includes(S.visaTab) ? S.visaTab : list[0];
  const c = S.research.countries[S.visaTab], st = S.priv.visa[S.visaTab] ||= {};
  const done = c.steps.filter(s => st[s[0]]).length;
  return `
  <div class="vh"><div><p class="eyebrow">Go</p><h1>Visa & move</h1><p>${acc.length ? 'Showing the countries where you have an admit.' : 'Preview of the steps for each country; this narrows to your admits later.'}</p></div></div>
  <div class="chips" style="margin-bottom:16px">${list.map(k => `<button class="chip ${k === S.visaTab ? 'on' : ''}" data-vtab="${k}">${esc(S.research.countries[k].name)}</button>`).join('')}</div>
  <div class="g2"><div class="panel"><h2>${esc(c.name)} · ${done}/${c.steps.length} done</h2>${meter(Math.round(done / c.steps.length * 100))}<div style="margin-top:10px">${c.steps.map(s => `
    <label class="check ${st[s[0]] ? 'done' : ''}"><input type="checkbox" data-vstep="${esc(s[0])}" ${st[s[0]] ? 'checked' : ''}><div><div class="t" style="font-weight:600">${esc(s[0])}</div>${s[1] ? `<div class="small muted">${esc(s[1])}</div>` : ''}</div><span class="when">${esc(s[2])}</span></label>`).join('')}</div></div>
  <div class="panel dark"><h2>Money you must show</h2><p style="margin:0 0 12px">${esc(c.proof)}</p><p class="small" style="color:var(--silk-muted)">Sources: ${(c.sources || []).map((u, i) => `<a href="${esc(u)}" target="_blank" rel="noopener" style="color:var(--copper-lt)">[${i + 1}]</a>`).join(' ')} · Always confirm with the embassy before paying anything.</p></div></div>`;
};

V.settings = () => {
  const pr = S.priv.profile, connected = !!S.priv.github?.token;
  return `
  <div class="vh"><div><p class="eyebrow">Settings</p><h1>Profile & setup</h1></div></div>
  <div class="g2"><div class="stack">
    <div class="panel"><h2>Profile (used for eligibility checks)</h2><div class="form">
      <label>GPA<input class="inp" type="number" step="0.01" data-prof="gpa" value="${pr.gpa}"></label>
      <label>GPA scale<input class="inp" type="number" data-prof="gpaScale" value="${pr.gpaScale}"></label>
      <label>IELTS overall<input class="inp" type="number" step="0.5" data-prof="ielts" value="${pr.ielts}"></label>
      <label>IELTS test date<input class="inp" type="date" data-prof="ieltsDate" value="${esc(pr.ieltsDate)}"></label>
      ${['L', 'R', 'W', 'S'].map(k => `<label>IELTS ${k}<input class="inp" type="number" step="0.5" data-sec="${k}" value="${pr.ieltsSections[k]}"></label>`).join('')}
      <label>₹ per €1 (optional, for budget)<input class="inp" type="number" step="0.01" data-prof="inrPerEur" value="${pr.inrPerEur ?? ''}"></label>
    </div></div>
    <div class="panel"><h2>Currency rates to EUR (approximate)</h2><div class="form">${Object.entries(S.research.rates).filter(([k]) => k !== 'EUR').map(([k, v]) => `<label>1 ${k} =<input class="inp" type="number" step="0.001" data-rate="${k}" value="${v}"></label>`).join('')}</div></div>
  </div><div class="stack">
    <div class="panel"><h2>Saving online</h2>${connected ? `<p style="margin:0 0 10px">${pill('ok', 'Connected')} Changes save to <code>${REPO}</code>.</p><button class="btn btn-line btn-sm" data-disconnect>Disconnect</button>` : `
      <p class="small" style="margin:0 0 10px">To save changes from any device, create a GitHub fine-grained token with access to only <b>${REPO}</b> and <b>Contents: Read and write</b>, then paste it here. It's stored inside your encrypted data.</p>
      <div class="row"><input class="inp" id="tok" type="password" placeholder="github_pat_…" style="flex:1"><button class="btn btn-copper btn-sm" data-connect>Connect</button></div>
      <p class="small"><a href="https://github.com/settings/personal-access-tokens/new?name=masters-tracker&description=Masters%20Journey%20saving&contents=write&expires_in=365" target="_blank" rel="noopener">Create the token →</a></p>`}</div>
    <div class="panel"><h2>Password</h2><div class="row"><input class="inp" id="npw" type="password" placeholder="New password" style="flex:1"><button class="btn btn-line btn-sm" data-pw>Change</button></div><p class="small muted">A longer password makes the encrypted data much harder to guess.</p></div>
    <div class="panel"><h2>Automation</h2>${automationHTML()}<p class="small"><a href="https://github.com/${REPO}/actions" target="_blank" rel="noopener">Run the page monitor now →</a></p></div>
    <div class="panel"><h2>Backup</h2><div class="row"><button class="btn btn-line btn-sm" data-export>Download my data</button></div></div>
  </div></div>`;
};

// ---------------------------------------------------------------- program drawer
function openProgram(id, edit = false) {
  const p = programs().find(x => x.id === id); if (!p) return;
  const e = eligibility(p), a = p._app, t = tuitionPerYearEUR(p), l = livingPerYearEUR(p);
  $('#dCat').textContent = `${COUNTRY[p.country] || p.country} · ${p.city || ''}`;
  $('#dTitle').textContent = p.program;
  $('#dSub').textContent = p.uni;
  const mon = monitorFor(p);
  const body = edit ? editForm(p) : `
    <div class="panel"><h2>Your application</h2><div class="form">
      <label>Stage${stageSelect(p)}</label>
      <label>Statement of purpose<select class="inp" data-sop="${esc(p.id)}">${DOC_STATUS.map(([v, lb]) => `<option value="${v}" ${a.sop === v ? 'selected' : ''}>${lb}</option>`).join('')}</select></label>
      <label class="full">Notes<textarea class="inp" data-notes="${esc(p.id)}" placeholder="Contacts, portal login hints (no passwords), interview prep…">${esc(a.notes)}</textarea></label>
    </div></div>
    <div class="panel"><h2>Eligibility ${eligPill(e)}</h2><ul class="list">${e.items.map(([lv, txt]) => `<li>${pill(lv === 'ok' ? 'ok' : lv === 'warn' ? 'warn' : 'bad', lv === 'ok' ? '✓' : lv === 'warn' ? '!' : '✕')}<div class="grow">${esc(txt)}</div></li>`).join('') || '<li class="muted">No numeric requirements recorded.</li>'}</ul>
      ${p.requirements?.text ? `<p class="small" style="margin:10px 0 0">${esc(p.requirements.text)}</p>` : ''}</div>
    <div class="panel"><h2>Key facts</h2><dl class="kv">
      <dt>Intake</dt><dd>${esc(p.intake)}</dd>
      ${Object.entries(p.dates || {}).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${fmtDate(v)} ${daysBadge(v, k)}</dd>`).join('')}
      ${p.deadlineNote ? `<dt>Note</dt><dd>${esc(p.deadlineNote)}</dd>` : ''}
      <dt>Tuition</dt><dd>${eur(t)} / yr ${p.tuition?.note ? `<div class="small muted">${esc(p.tuition.note)}</div>` : ''}</dd>
      <dt>Living</dt><dd>${eur(l)} / yr <span class="small muted">(visa minimum)</span></dd>
      <dt>English</dt><dd>${esc(p.requirements?.english || '—')}</dd>
      <dt>GPA</dt><dd>${esc(p.requirements?.gpa || '—')}</dd>
      <dt>Portal</dt><dd>${esc(p.portal || '—')}</dd>
      <dt>Links</dt><dd>${p.links?.program ? `<a href="${esc(p.links.program)}" target="_blank" rel="noopener">Programme page ↗</a>` : ''} ${p.links?.apply ? ` · <a href="${esc(p.links.apply)}" target="_blank" rel="noopener">Apply ↗</a>` : ''}</dd>
    </dl></div>
    <div class="panel"><h2>Documents · ${readiness(p)}%</h2>${(p.docs || []).map(k => { const ok = k === 'sop' ? a.sop === 'ready' : docDone(k); return `<div class="check ${ok ? 'done' : ''}">${pill(ok ? 'ok' : 'mute', ok ? '✓' : '·')}<div class="t">${esc(DOCS[k]?.[0] || k)}</div></div>`; }).join('')}<p class="small muted">Change statuses under Documents; the SOP is tracked above.</p></div>
    <div class="panel"><h2>Research log</h2>
      <p class="small" style="margin:0 0 8px">Last verified: <b>${fmtDate(p.lastVerified)}</b>${p.verify ? ' · some facts still need confirming on the official page' : ''}</p>
      ${(p._updates?.log || []).slice().reverse().map(x => `<div class="alert info"><div><b>${fmtDate(x.date)}</b>${esc(x.text)}${x.source ? ` <a href="${esc(x.source)}" target="_blank" rel="noopener">source</a>` : ''}</div></div>`).join('')}
      ${mon.map(m => `<div class="small" style="margin-top:8px"><b>Monitor:</b> <a href="${esc(m.url)}" target="_blank" rel="noopener">${esc(m.url.replace(/^https?:\/\//, '').slice(0, 60))}</a> · ${m.status === 'ok' ? `checked ${fmtDate(m.lastChecked?.slice(0, 10))}${m.lastChanged ? `, changed ${fmtDate(m.lastChanged.slice(0, 10))}` : ''}` : m.status === 'error' ? 'could not load' : 'not checked yet'}${(m.newDates || m.dates || []).slice(0, 3).map(d => `<div class="snip">${esc(d)}</div>`).join('')}</div>`).join('')}
    </div>
    <div class="row"><button class="btn btn-line btn-sm" data-edit="${esc(p.id)}">Edit programme facts</button>${p._custom ? `<button class="btn btn-line btn-sm" data-delp="${esc(p.id)}">Delete</button>` : ''}</div>`;
  $('#dBody').innerHTML = body;
  $('#drawer').classList.add('open');
  document.body.style.overflow = 'hidden';
  S.openId = id;
}
function closeDrawer() { $('#drawer').classList.remove('open'); document.body.style.overflow = ''; S.openId = null; }
function editForm(p) {
  const f = (k, label, type = 'text', cls = '') => `<label class="${cls}">${label}<input class="inp" type="${type}" data-ed="${k}" value="${esc(getPath(p, k) ?? '')}"></label>`;
  return `<div class="panel"><h2>Edit facts</h2><div class="form">
    ${f('uni', 'University', 'text', 'full')}${f('program', 'Programme', 'text', 'full')}
    <label>Country<select class="inp" data-ed="country">${Object.entries(COUNTRY).map(([k, v]) => `<option value="${k}" ${p.country === k ? 'selected' : ''}>${v}</option>`).join('')}</select></label>${f('city', 'City')}
    ${f('intake', 'Intake')}${f('fields', 'Fields (comma separated)')}
    ${f('dates.opens', 'Opens', 'date')}${f('dates.deadline', 'Deadline', 'date')}${f('dates.docs', 'Documents due', 'date')}${f('dates.results', 'Results', 'date')}
    ${f('deadlineNote', 'Deadline note', 'text', 'full')}
    ${f('tuition.amount', 'Tuition amount', 'number')}<label>Currency / per<span class="row"><input class="inp" data-ed="tuition.currency" value="${esc(p.tuition?.currency || 'EUR')}" style="width:80px"><select class="inp" data-ed="tuition.per">${['year', 'semester', 'total'].map(x => `<option ${p.tuition?.per === x ? 'selected' : ''}>${x}</option>`).join('')}</select></span></label>
    ${f('tuition.note', 'Tuition note', 'text', 'full')}
    ${f('requirements.gpaPct', 'Min GPA %', 'number')}${f('requirements.ielts', 'Min IELTS', 'number')}
    ${f('requirements.ieltsSection', 'Min IELTS section', 'number')}${f('requirements.english', 'English (text)')}
    ${f('requirements.text', 'Requirements (text)', 'text', 'full')}
    ${f('links.program', 'Programme URL', 'url', 'full')}${f('links.apply', 'Apply URL', 'url', 'full')}${f('portal', 'Portal')}
    ${f('docs', 'Document keys (comma separated)')}
  </div><div class="row" style="margin-top:14px"><button class="btn btn-copper btn-sm" data-saveedit="${esc(p.id)}">Save</button><button class="btn btn-line btn-sm" data-open="${esc(p.id)}">Cancel</button></div>
  <p class="small muted">Programme facts are public (no personal data). Saved facts are marked as verified today.</p></div>`;
}
function saveEdit(id) {
  let base = S.research.programs.find(x => x.id === id) || S.priv.custom.find(x => x.id === id);
  if (!base) { const f = (S.updates.add || []).find(x => x.id === id); if (!f) return; base = clone(f); S.research.programs.push(base); }
  document.querySelectorAll('[data-ed]').forEach(el => {
    let v = el.value.trim(), k = el.dataset.ed;
    if (['fields', 'docs'].includes(k)) v = v ? v.split(',').map(s => s.trim()).filter(Boolean) : [];
    else if (el.type === 'number') v = v === '' ? null : Number(v);
    else if (el.type === 'date' && !v) v = undefined;
    if (v === undefined) { const ks = k.split('.'); const parent = getPath(base, ks.slice(0, -1).join('.')) ; if (parent && ks.length > 1) delete parent[ks.at(-1)]; return; }
    setPath(base, k, v);
  });
  base.lastVerified = new Date().toISOString().slice(0, 10); base.verify = false;
  if (S.updates.changes?.[id]?.set) Object.keys(S.updates.changes[id].set).forEach(k => delete S.updates.changes[id].set[k]);
  if (S.priv.custom.includes(base)) queueSave('private'); else queueSave('research', `Update facts: ${base.uni}`);
  openProgram(id); render(); toast('Saved');
}

// ---------------------------------------------------------------- compare & ics & misc
function compareHTML() {
  const ps = programs().filter(p => S.compare.includes(p.id));
  const rows = [['Country', p => COUNTRY[p.country]], ['Deadline', p => fmtDate(p.dates?.deadline)], ['Eligibility', p => eligPill(eligibility(p))], ['Tuition / yr', p => eur(tuitionPerYearEUR(p))], ['Living / yr', p => eur(livingPerYearEUR(p))], ['English', p => esc(p.requirements?.english)], ['GPA', p => esc(p.requirements?.gpa)], ['Documents ready', p => readiness(p) + '%'], ['Stage', p => STAGE_LABEL[p._app.stage]]];
  return `<div class="panel"><h2>Compare</h2><div class="tw"><table class="t"><thead><tr><th></th>${ps.map(p => `<th>${esc(p.uni)}<div class="small" style="text-transform:none;letter-spacing:0">${esc(p.program)}</div></th>`).join('')}</tr></thead><tbody>${rows.map(([l, fn]) => `<tr><td><b>${l}</b></td>${ps.map(p => `<td>${fn(p)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>
  <div class="row" style="margin-top:12px"><button class="btn btn-line btn-sm" data-clearcmp>Clear comparison</button></div></div>`;
}
function downloadICS() {
  const pad = s => s.replace(/-/g, '');
  const lines = ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//Masters Journey//EN', 'CALSCALE:GREGORIAN'];
  events().filter(e => daysTo(e.date) >= 0).forEach((e, i) => {
    const next = new Date(e.date + 'T00:00:00'); next.setDate(next.getDate() + 1);
    lines.push('BEGIN:VEVENT', `UID:${pad(e.date)}-${i}@masters-journey`, `DTSTAMP:${new Date().toISOString().replace(/[-:]/g, '').slice(0, 15)}Z`, `DTSTART;VALUE=DATE:${pad(e.date)}`, `DTEND;VALUE=DATE:${next.toISOString().slice(0, 10).replace(/-/g, '')}`,
      `SUMMARY:${(e.label + (e.p ? ' – ' + e.p.uni : '')).replace(/[,;]/g, ' ')}`, ...(e.kind === 'deadline' ? ['BEGIN:VALARM', 'TRIGGER:-P7D', 'ACTION:DISPLAY', 'DESCRIPTION:Deadline in 7 days', 'END:VALARM'] : []), 'END:VEVENT');
  });
  lines.push('END:VCALENDAR');
  const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([lines.join('\r\n')], { type: 'text/calendar' })); a.download = 'masters-deadlines.ics'; a.click();
}
function addProgram() {
  const id = 'custom-' + Math.random().toString(36).slice(2, 8);
  S.priv.custom.push({ id, uni: 'New university', program: 'New programme', country: 'DE', city: '', fields: [], intake: '', dates: {}, tuition: { amount: null, currency: 'EUR', per: 'year' }, requirements: {}, links: {}, docs: ['transcripts', 'ielts', 'cv', 'sop', 'lor1', 'lor2', 'passport'], watch: [], verify: true });
  app(id).stage = 'shortlisted';
  queueSave('private'); openProgram(id, true);
}

// ---------------------------------------------------------------- render & events
function render() {
  $('#nav').innerHTML = VIEWS.map(([k, l]) => `<button class="${S.view === k ? 'on' : ''}" data-go="${k}">${l}${k === 'dash' && alerts().length ? `<span class="n">${alerts().length}</span>` : ''}</button>`).join('') + `<div class="foot">Research updated ${fmtDate(S.research.updated)}<br>${S.research.programs.length} programmes tracked</div>`;
  $('#view').innerHTML = (S.view === 'programs' && S.showCompare ? compareHTML() : '') + V[S.view]();
}
function bind() {
  document.addEventListener('click', async e => {
    const t = e.target.closest('[data-go],[data-open],[data-country],[data-move],[data-dismiss],[data-ics],[data-add],[data-compare],[data-clearcmp],[data-vtab],[data-edit],[data-saveedit],[data-delp],[data-connect],[data-disconnect],[data-pw],[data-export],[data-milestone],[data-delms],#lockBtn,#dClose,.scrim');
    if (!t) return;
    const d = t.dataset;
    if (d.go) { S.view = d.go; S.showCompare = false; closeDrawer(); render(); scrollTo(0, 0); }
    else if (d.open) openProgram(d.open);
    else if (d.country !== undefined && t.classList.contains('chip')) { S.filters.country = d.country; render(); }
    else if (d.move) { const a = app(d.move), i = BOARD.indexOf(a.stage), n = Math.max(0, Math.min(BOARD.length - 1, i + Number(d.dir))); a.stage = BOARD[i < 0 ? 0 : n]; queueSave(); render(); }
    else if (d.dismiss) { (S.priv.dismissed ||= {})[d.dismiss] = new Date().toISOString().slice(0, 10); queueSave(); render(); }
    else if (d.ics !== undefined) downloadICS();
    else if (d.add !== undefined) addProgram();
    else if (d.compare !== undefined) { S.showCompare = true; render(); scrollTo(0, 0); }
    else if (d.clearcmp !== undefined) { S.compare = []; S.showCompare = false; render(); }
    else if (d.vtab) { S.visaTab = d.vtab; render(); }
    else if (d.edit) openProgram(d.edit, true);
    else if (d.saveedit) saveEdit(d.saveedit);
    else if (d.delp) { if (t.dataset.armed) { S.priv.custom = S.priv.custom.filter(x => x.id !== d.delp); delete S.priv.apps[d.delp]; queueSave(); closeDrawer(); render(); } else { t.dataset.armed = 1; t.textContent = 'Click again to delete'; } }
    else if (d.connect !== undefined) connectGitHub();
    else if (d.disconnect !== undefined) disconnectGitHub();
    else if (d.pw !== undefined) changePassword();
    else if (d.export !== undefined) { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([JSON.stringify({ ...S.priv, github: { token: '' } }, null, 1)], { type: 'application/json' })); a.download = 'masters-journey-backup.json'; a.click(); }
    else if (d.milestone !== undefined) { const title = prompt('Milestone (e.g. "Book VFS appointment")'); if (!title) return; const date = prompt('Date (YYYY-MM-DD)'); if (!/^\d{4}-\d\d-\d\d$/.test(date || '')) return toast('Use the format YYYY-MM-DD'); S.priv.milestones.push({ id: Math.random().toString(36).slice(2, 8), title, date }); queueSave(); render(); }
    else if (d.delms) { S.priv.milestones = S.priv.milestones.filter(m => m.id !== d.delms); queueSave(); render(); }
    else if (t.id === 'lockBtn') lock();
    else if (t.id === 'dClose' || t.classList.contains('scrim')) closeDrawer();
  });
  document.addEventListener('change', e => {
    const t = e.target, d = t.dataset;
    if (d.stage) { app(d.stage).stage = t.value; if (t.value === 'submitted') app(d.stage).submittedOn = new Date().toISOString().slice(0, 10); queueSave(); render(); if (S.openId) openProgram(S.openId); }
    else if (d.sop) { app(d.sop).sop = t.value; queueSave(); render(); }
    else if (d.notes) { app(d.notes).notes = t.value; queueSave(); }
    else if (d.doc) { S.priv.documents[d.doc].status = t.value; queueSave(); render(); }
    else if (d.exp) { S.priv.documents[d.exp].expiry = t.value; queueSave(); }
    else if (d.cmp) { S.compare = t.checked ? [...new Set([...S.compare, d.cmp])].slice(-3) : S.compare.filter(x => x !== d.cmp); render(); }
    else if (d.f) { S.filters[d.f] = t.value; render(); }
    else if (d.vstep) { (S.priv.visa[S.visaTab] ||= {})[d.vstep] = t.checked ? new Date().toISOString().slice(0, 10) : undefined; if (!t.checked) delete S.priv.visa[S.visaTab][d.vstep]; queueSave(); render(); }
    else if (d.prof) { const num = t.type === 'number'; S.priv.profile[d.prof] = num ? (t.value === '' ? null : Number(t.value)) : t.value; queueSave(); }
    else if (d.sec) { S.priv.profile.ieltsSections[d.sec] = Number(t.value); queueSave(); }
    else if (d.rate) { S.research.rates[d.rate] = Number(t.value); queueSave('research', 'Update currency rates'); }
  });
  document.addEventListener('input', e => { if (e.target.id === 'q') { S.filters.q = e.target.value; clearTimeout(bind.qt); bind.qt = setTimeout(() => { render(); const q = $('#q'); q.focus(); q.setSelectionRange(q.value.length, q.value.length); }, 250); } });
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDrawer(); });
}
async function connectGitHub() {
  const tok = $('#tok').value.trim(); if (!tok) return;
  setSync('Checking token…');
  const r = await fetch(`https://api.github.com/repos/${REPO}`, { headers: { Authorization: 'Bearer ' + tok, Accept: 'application/vnd.github+json' } });
  if (!r.ok) return setSync('Token cannot access ' + REPO, 'err');
  const j = await r.json(); if (j.permissions && !j.permissions.push) return setSync('Token has no write access', 'err');
  S.priv.github = { token: tok }; queueSave('private'); render(); toast('Connected. Changes now save online.');
}
async function disconnectGitHub() {
  const tok = S.priv.github.token; S.priv.github.token = '';
  try { const text = JSON.stringify(await encryptBlob(S.priv, S.key, S.salt, S.iter)); S.priv.github.token = tok; await putFile('private.enc.json', text, 'Remove GitHub token'); }
  catch (e) { S.priv.github.token = tok; return toast('Could not disconnect: ' + e.message); }
  S.priv.github.token = ''; setSync('Read-only until GitHub is connected'); render(); toast('Disconnected. The token was removed from your saved data.');
}
async function changePassword() {
  const pw = $('#npw').value; if (!pw || pw.length < 4) return toast('Use at least 4 characters');
  S.salt = crypto.getRandomValues(new Uint8Array(16));
  const raw = await deriveRaw(pw, S.salt, S.iter); S.key = await importKey(raw);
  if (store.get('mj_key')) store.set('mj_key', JSON.stringify({ salt: b64(S.salt), raw: b64(raw) }));
  queueSave('private'); $('#npw').value = ''; toast('Password changed');
}

// ---------------------------------------------------------------- lock / unlock
async function unlock(pw, remember) {
  const blob = await loadPublic('private.enc.json', null);
  if (!blob) throw new Error('Could not load your encrypted data.');
  S.salt = unb64(blob.salt); S.iter = blob.iter;
  let raw;
  if (pw == null) { const saved = JSON.parse(store.get('mj_key') || store.sget('mj_key') || 'null'); if (!saved || saved.salt !== blob.salt) throw new Error('locked'); raw = unb64(saved.raw); }
  else raw = await deriveRaw(pw, S.salt, S.iter);
  S.key = await importKey(raw);
  try { S.priv = await decryptBlob(blob, S.key); } catch { throw new Error('Wrong password.'); }
  S.priv.apps ||= {}; S.priv.documents ||= {}; S.priv.visa ||= {}; S.priv.milestones ||= []; S.priv.custom ||= []; S.priv.github ||= { token: '' };
  if (pw != null) { const v = JSON.stringify({ salt: blob.salt, raw: b64(raw) }); remember ? store.set('mj_key', v) : store.sset('mj_key', v); }
  [S.research, S.updates, S.monitor] = await Promise.all([loadPublic('research.json', null), loadPublic('updates.json', { runs: [], changes: {} }), loadPublic('monitor.json', { pages: {} })]);
  if (!S.research) throw new Error('Could not load research.json.');
  $('#lock').hidden = true; $('#app').hidden = false;
  setSync(S.priv.github.token ? 'Synced' : 'Read-only until GitHub is connected', S.priv.github.token ? 'ok' : '');
  render();
}
function lock() { store.del('mj_key'); S.priv = null; S.key = null; location.reload(); }

document.addEventListener('DOMContentLoaded', async () => {
  bind();
  $('#lockForm').addEventListener('submit', async e => {
    e.preventDefault(); const btn = $('#lockGo'); btn.disabled = true; $('#lockErr').textContent = 'Unlocking…';
    try { await unlock($('#pw').value, $('#remember').checked); } catch (err) { $('#lockErr').textContent = err.message; } finally { btn.disabled = false; }
  });
  try { await unlock(null); } catch { $('#pw').focus(); }
});
