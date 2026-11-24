'use strict';
/* Asset Portal SPA — vanilla JS, hash routing, no build step. */

// ------------------------------------------------------------------ helpers
const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];
const esc = (v) => (v === null || v === undefined ? '' : String(v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])));
const titleCase = (s) => (s ? String(s).replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()) : '');
const fmtDate = (s) => (s ? String(s).slice(0, 10) : '');
const fmtDT = (s) => (s ? new Date(s).toLocaleString() : '');
const fmtNum = (n, d = 0) => (n === null || n === undefined || n === '' ? '' : Number(n).toLocaleString(undefined, { maximumFractionDigits: d }));
const money = (n) => (n === null || n === undefined || n === '' ? '' : Number(n).toLocaleString(undefined, { style: 'currency', currency: S.me?.currency || 'USD' }));
const gbFromMb = (mb) => (mb ? `${(mb / 1024).toFixed(mb >= 10240 ? 0 : 1)} GB` : '');
function ago(s) {
  if (!s) return 'never';
  const sec = (Date.now() - Date.parse(s)) / 1000;
  if (sec < 60) return 'just now';
  if (sec < 3600) return `${Math.floor(sec / 60)} min ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)} h ago`;
  return `${Math.floor(sec / 86400)} d ago`;
}
const S = { me: null, meta: null, alertCount: 0 };
const hasPerm = (p) => (S.me?.perms || []).includes(p);
const ROUTE_MODULE = { dashboard: 'dashboard', alerts: 'alerts', assets: 'assets', labels: 'assets', checkouts: 'assets', software: 'software', discovery: 'discovery',
  agents: 'agents', monitoring: 'monitoring', licenses: 'licenses', contracts: 'contracts', people: 'people', locations: 'locations', departments: 'locations',
  map: 'locations', stock: 'stock', import: 'import', catalog: 'catalog', reports: 'reports', settings: 'admin', users: 'admin', groups: 'admin', 'security-center': 'admin', audit: 'admin' };
const moduleOf = (id) => ROUTE_MODULE[id] || 'dashboard';
const navAllowed = (id) => { const m = moduleOf(id); return m === 'admin' ? hasPerm('admin.all') : m === 'import' ? hasPerm('import.run') : hasPerm(`${m}.view`); };
/** can('viewer'|'tech'|'admin') — answered from the signed-in user's permissions for the current page's module. */
const can = (role) => {
  if (role === 'admin') return hasPerm('admin.all');
  if (role === 'viewer') return true;
  const m = S.module || 'assets';
  return m === 'monitoring' ? hasPerm('monitoring.view') : m === 'import' ? hasPerm('import.run') : hasPerm(`${m}.edit`);
};

async function api(method, path, body, opts = {}) {
  const init = { method, headers: { 'X-Requested-With': 'fetch' }, credentials: 'same-origin' };
  if (opts.background) init.headers['X-Background'] = '1';
  if (body !== undefined) {
    if (typeof body === 'string') { init.body = body; init.headers['Content-Type'] = 'text/csv'; }
    else { init.body = JSON.stringify(body); init.headers['Content-Type'] = 'application/json'; }
  }
  const res = await fetch(path, init);
  if (res.status === 401 && !opts.noRedirect) { S.me = null; renderLogin(); throw new Error('Not logged in'); }
  const data = res.headers.get('content-type')?.includes('json') ? await res.json() : await res.text();
  if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
  return data;
}
const GET = (p) => api('GET', p);
const qs = (o) => new URLSearchParams(Object.entries(o).filter(([, v]) => v !== '' && v !== null && v !== undefined)).toString();

function toast(msg, err = false) {
  const t = document.createElement('div');
  t.className = 'toast' + (err ? ' err' : '');
  t.textContent = msg;
  $('#toasts').appendChild(t);
  setTimeout(() => t.remove(), err ? 6000 : 3000);
}
const guard = (fn) => async (...a) => { try { await fn(...a); } catch (e) { if (e.message !== 'Not logged in') toast(e.message, true); } };

const pillClass = {
  in_use: 'ok', in_stock: 'info', in_repair: 'warn', reserved: 'info', retired: '', disposed: '', lost: 'crit',
  critical: 'crit', warning: 'warn', info: 'info', authorized: 'ok', prohibited: 'crit', neutral: '',
  compliant: 'ok', over: 'crit', expired: 'crit', 'non-compliant': 'crit', unknown: '',
  ok: 'ok', warn: 'warn', info: 'info', crit: 'crit',
};
const pill = (v, label) => `<span class="pill ${pillClass[v] ?? ''}">${esc(label || titleCase(v))}</span>`;

// ------------------------------------------------------------------ modal
function modal({ title, body, submitLabel = 'Save', onSubmit, wide = false, footer = true }) {
  const back = document.createElement('div');
  back.className = 'modal-back';
  back.innerHTML = `<form class="modal" style="${wide ? 'max-width:900px' : ''}" novalidate>
    <header>${esc(title)}<button type="button" data-close aria-label="Close">&times;</button></header>
    <div class="body">${body}</div>
    ${footer ? `<footer><button type="button" class="btn" data-close>Cancel</button>${onSubmit ? `<button class="btn primary" type="submit">${esc(submitLabel)}</button>` : ''}</footer>` : ''}
  </form>`;
  const close = () => back.remove();
  back.addEventListener('click', (e) => { if (e.target === back || e.target.closest('[data-close]')) close(); });
  back.querySelector('form').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!onSubmit) return;
    const btn = back.querySelector('button[type=submit]');
    btn.disabled = true;
    try { if ((await onSubmit(back.querySelector('form'))) !== false) close(); }
    catch (err) { toast(err.message, true); }
    finally { btn.disabled = false; }
  });
  document.body.appendChild(back);
  back.querySelector('input,select,textarea')?.focus();
  return back;
}
const confirmBox = (msg) => new Promise((resolve) => {
  const m = modal({ title: 'Please confirm', body: `<p>${esc(msg)}</p>`, submitLabel: 'Confirm', onSubmit: () => resolve(true) });
  m.querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', () => resolve(false)));
});

/** field: {name,label,type,options:[{value,label}],full,required,placeholder,help} */
function fieldHtml(f, v) {
  const id = `f_${f.name}`;
  const val = v ?? '';
  let input;
  if (f.type === 'select') {
    input = `<select id="${id}" name="${f.name}">${f.blank === false ? '' : '<option value="">—</option>'}${f.options.map((o) =>
      `<option value="${esc(o.value)}" ${String(o.value) === String(val) ? 'selected' : ''}>${esc(o.label)}</option>`).join('')}</select>`;
  } else if (f.type === 'textarea') input = `<textarea id="${id}" name="${f.name}" placeholder="${esc(f.placeholder || '')}">${esc(val)}</textarea>`;
  else input = `<input id="${id}" name="${f.name}" type="${f.type || 'text'}" value="${esc(val)}" ${f.required ? 'required' : ''} placeholder="${esc(f.placeholder || '')}" ${f.type === 'number' ? 'step="any"' : ''}>`;
  return `<div class="field ${f.full ? 'full' : ''}"><label for="${id}">${esc(f.label)}${f.required ? ' *' : ''}</label>${input}${f.help ? `<span class="muted small">${esc(f.help)}</span>` : ''}</div>`;
}
const formValues = (form) => Object.fromEntries(new FormData(form).entries());
function formModal({ title, fields, values = {}, onSubmit, submitLabel }) {
  return modal({
    title, submitLabel,
    body: `<div class="form-grid">${fields.map((f) => fieldHtml(f, values[f.name])).join('')}</div>`,
    onSubmit: async (form) => {
      const vals = formValues(form);
      for (const f of fields) if (f.required && !vals[f.name]) throw new Error(`${f.label} is required`);
      return onSubmit(vals);
    },
  });
}
const opts = (arr, lbl = titleCase) => arr.map((x) => (typeof x === 'object' ? { value: x.id, label: x.name } : { value: x, label: lbl(x) }));

function bars(rows, { label = (r) => r.k, value = (r) => r.n, href } = {}) {
  if (!rows.length) return '<div class="empty">No data yet</div>';
  const max = Math.max(...rows.map(value), 1);
  return `<div class="bars">${rows.map((r) => `<div class="bar-row"><span class="lbl" title="${esc(label(r))}">${href ? `<a href="${href(r)}">${esc(label(r))}</a>` : esc(label(r))}</span>
    <span class="bar"><span style="width:${(value(r) / max) * 100}%"></span></span><span class="n">${fmtNum(value(r))}</span></div>`).join('')}</div>`;
}
function table(cols, rows, { empty = 'Nothing here yet', rowAttr } = {}) {
  if (!rows.length) return `<div class="table-wrap"><div class="empty">${esc(empty)}</div></div>`;
  return `<div class="table-wrap"><table><thead><tr>${cols.map((c) => `<th class="${c.num ? 'num' : ''}">${c.label ?? titleCase(c.key)}</th>`).join('')}</tr></thead>
    <tbody>${rows.map((r) => `<tr ${rowAttr ? rowAttr(r) : ''}>${cols.map((c) => `<td class="${c.num ? 'num' : ''}">${c.render ? c.render(r) : esc(r[c.key])}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
}
const usageBar = (used, total, invert = false) => {
  const pct = total ? Math.min(100, (used / total) * 100) : 0;
  const cls = invert ? (pct > 90 ? 'crit' : pct > 80 ? 'warn' : '') : '';
  return `<div class="usage ${cls}" title="${pct.toFixed(0)}%"><span style="width:${pct}%"></span></div>`;
};

// ------------------------------------------------------------------ icons
const ICON_PATHS = {
  dashboard: '<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>',
  bell: '<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/>',
  monitor: '<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>',
  layers: '<path d="m12 2 9 5-9 5-9-5 9-5z"/><path d="m3 12 9 5 9-5"/><path d="m3 17 9 5 9-5"/>',
  radar: '<path d="M19.07 4.93A10 10 0 1 0 22 12"/><path d="M16.24 7.76A6 6 0 1 0 18 12"/><circle cx="12" cy="12" r="2"/><path d="m13.4 10.6 6-6"/>',
  download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/><path d="M12 15V3"/>',
  key: '<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6M15.5 7.5l3 3L22 7l-3-3"/>',
  file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M16 13H8M16 17H8M10 9H8"/>',
  users: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/>',
  pin: '<path d="M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0z"/><circle cx="12" cy="10" r="3"/>',
  building: '<rect x="4" y="2" width="16" height="20" rx="2"/><path d="M9 22v-4h6v4M8 6h.01M16 6h.01M12 6h.01M12 10h.01M12 14h.01M16 10h.01M16 14h.01M8 10h.01M8 14h.01"/>',
  chart: '<path d="M3 3v18h18"/><rect x="7" y="12" width="3" height="5" rx=".5"/><rect x="12" y="8" width="3" height="9" rx=".5"/><rect x="17" y="5" width="3" height="12" rx=".5"/>',
  settings: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
  shieldCheck: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
  lock: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
  list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
  search: '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>',
  menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
  moon: '<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9z"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  refresh: '<path d="M21 12a9 9 0 1 1-2.64-6.36L21 8"/><path d="M21 3v5h-5"/>',
  x: '<path d="M18 6 6 18M6 6l12 12"/>',
  check: '<path d="M20 6 9 17l-5-5"/>',
  info: '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>',
  alert: '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4M12 17h.01"/>',
  laptop: '<rect x="4" y="4" width="16" height="11" rx="2"/><path d="M2 20h20"/>',
  server: '<rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="13" width="20" height="8" rx="2"/><path d="M6 7h.01M6 17h.01"/>',
  printer: '<path d="M6 9V2h12v7"/><rect x="2" y="9" width="20" height="9" rx="2"/><path d="M6 14h12v8H6z"/>',
  network: '<rect x="9" y="2" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="16" y="16" width="6" height="6" rx="1"/><path d="M12 8v4M5 16v-4h14v4"/>',
  phone: '<rect x="6" y="2" width="12" height="20" rx="2"/><path d="M11 18h2"/>',
  box: '<path d="m21 8-9-5-9 5v8l9 5 9-5z"/><path d="m3 8 9 5 9-5M12 13v8"/>',
  copy: '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
  print: '<path d="M6 9V2h12v7"/><rect x="2" y="9" width="20" height="9" rx="2"/><path d="M6 14h12v8H6z"/>',
  upload: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m17 8-5-5-5 5M12 3v12"/>',
  tag: '<path d="M12 2H2v10l9.29 9.29a1 1 0 0 0 1.41 0l8.59-8.59a1 1 0 0 0 0-1.41z"/><circle cx="7" cy="7" r="1.5"/>',
  dollar: '<path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/>',
  cpu: '<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3"/>',
  activity: '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
  camera: '<path d="M14.5 4h-5L7 7H4a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-3z"/><circle cx="12" cy="13" r="3.5"/>',
  eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/>',
  mapPin: '<path d="M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0z"/><circle cx="12" cy="10" r="3"/>',
  clock: '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
  trash: '<path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/>',
  power: '<path d="M18.36 6.64a9 9 0 1 1-12.73 0M12 2v10"/>',
  wifi: '<path d="M5 13a10 10 0 0 1 14 0M8.5 16.5a5 5 0 0 1 7 0M2 8.8a15 15 0 0 1 20 0"/><path d="M12 20h.01"/>',
};
const icon = (name, cls = '') => `<svg class="i ${cls}" viewBox="0 0 24 24" aria-hidden="true">${ICON_PATHS[name] || ''}</svg>`;
const TYPE_ICON = { workstation: 'monitor', laptop: 'laptop', server: 'server', virtual_machine: 'cpu', monitor: 'monitor', printer: 'printer',
  network: 'network', storage: 'server', phone: 'phone', tablet: 'phone', peripheral: 'box', ups: 'box', other: 'box' };
const PALETTE = ['var(--c1)', 'var(--c2)', 'var(--c3)', 'var(--c4)', 'var(--c5)', 'var(--c6)', 'var(--c7)', 'var(--c8)'];

function donut(rows, { label = (r) => titleCase(r.k), value = (r) => r.n, center = 'Total', href } = {}) {
  const total = rows.reduce((s, r) => s + value(r), 0);
  if (!total) return '<div class="empty">No data yet</div>';
  const R = 52, C = 2 * Math.PI * R;
  let off = 0;
  const segs = rows.map((r, i) => {
    const len = (value(r) / total) * C;
    const s = `<circle cx="70" cy="70" r="${R}" fill="none" stroke="${PALETTE[i % PALETTE.length]}" stroke-width="18" stroke-dasharray="${len} ${C - len}" stroke-dashoffset="${-off}" transform="rotate(-90 70 70)"><title>${esc(label(r))}: ${value(r)}</title></circle>`;
    off += len;
    return s;
  }).join('');
  return `<div class="donut-wrap"><svg class="donut" viewBox="0 0 140 140" role="img" aria-label="${esc(center)} breakdown">
      <circle cx="70" cy="70" r="${R}" fill="none" stroke="var(--surface-3)" stroke-width="18"/>${segs}
      <text x="70" y="72" text-anchor="middle">${fmtNum(total)}</text><text class="sub" x="70" y="90" text-anchor="middle">${esc(center)}</text></svg>
    <div class="legend">${rows.map((r, i) => `<div><i style="background:${PALETTE[i % PALETTE.length]}"></i><span>${href ? `<a href="${href(r)}">${esc(label(r))}</a>` : esc(label(r))}</span><b>${fmtNum(value(r))}</b></div>`).join('')}</div></div>`;
}
const callout = (kind, html, ic = kind === 'ok' ? 'shieldCheck' : kind === 'crit' || kind === 'warn' ? 'alert' : 'info') => `<div class="callout ${kind}">${icon(ic)}<div>${html}</div></div>`;
const initials = (s) => String(s || '?').split(/[\s._@-]+/).filter(Boolean).slice(0, 2).map((w) => w[0].toUpperCase()).join('');

// ------------------------------------------------------------------ shell
const NAV = [
  ['Overview', [['dashboard', 'Dashboard', 'dashboard'], ['alerts', 'Alerts', 'bell']]],
  ['Inventory', [['assets', 'Assets', 'monitor'], ['stock', 'Accessories & stock', 'box'], ['software', 'Software', 'layers'], ['map', 'Locations map', 'mapPin'],
    ['import', 'Bulk import', 'upload'], ['discovery', 'Network discovery', 'radar'], ['agents', 'Agents & deployment', 'download']]],
  ['Monitoring', [['monitoring', 'Activity & screens', 'activity', 'tech']]],
  ['Management', [['catalog', 'Catalog', 'layers'], ['licenses', 'Licenses', 'key'], ['contracts', 'Contracts', 'file'], ['checkouts', 'Check-outs', 'tag'], ['people', 'People', 'users'], ['locations', 'Locations', 'pin'], ['departments', 'Departments', 'building']]],
  ['Insights', [['reports', 'Reports', 'chart']]],
  ['Administration', [['settings', 'Settings', 'settings', 'admin'], ['users', 'Users & roles', 'shield', 'admin'], ['groups', 'Permission groups', 'users', 'admin'], ['security-center', 'Security center', 'shieldCheck', 'admin'], ['audit', 'Audit log', 'list', 'admin']]],
];

function renderShell() {
  $('#root').innerHTML = `<div class="app ${prefGet('sideCollapsed', false) ? 'collapsed' : ''}" id="app">
    <aside class="side" id="side">
      <div class="brand"><img src="logo-192.png" alt=""><div class="brand-txt"><b>Asset Portal</b><small>${esc(S.me.org_name || '')}</small></div>
        <button class="collapse-btn" id="collapseBtn" title="Collapse sidebar" aria-label="Collapse sidebar">${icon('menu', 'sm')}</button></div>
      <nav>${NAV.map(([g, items]) => {
        const vis = items.filter((i) => navAllowed(i[0]));
        return vis.length ? `<div class="nav-group">${g}</div>${vis.map(([id, label, ic]) => `<a href="#/${id}" data-nav="${id}" title="${label}">${icon(ic)}<span>${label}</span>${id === 'alerts' ? '<span class="count" id="alertBadge" hidden></span>' : ''}</a>`).join('')}` : '';
      }).join('')}</nav>
      <div class="side-foot">${icon('lock', 'sm')} Encrypted agent channel</div>
    </aside>
    <div class="main">
      ${S.me.must_change ? `<div class="banner">${icon('alert')} You are using an initial password. <a href="#/security">Change it now</a> to unlock editing.</div>` : ''}
      ${S.me.must_enable_2fa ? `<div class="banner">${icon('shield')} Your organization requires two-factor authentication for administrators. <a href="#/security">Set it up now</a>.</div>` : ''}
      <header class="topbar">
        <button class="btn menu-btn" id="menuBtn" aria-label="Open menu">${icon('menu')}</button>
        <div class="search">${icon('search', 'sm')}<input type="search" id="gsearch" placeholder="Search assets, serials, IPs, users, software…" autocomplete="off" aria-label="Search"><kbd class="kbd-hint" id="palHint" title="Command palette">Ctrl K</kbd><div class="search-results" id="gresults" hidden></div></div>
        <div class="top-actions">
          ${can('tech') ? `<div class="dd"><button class="btn primary" id="quickBtn">${icon('plus', 'sm')} New</button><div class="dd-menu right" id="quickMenu" hidden>
            <button class="dd-item" data-q="asset">${icon('monitor', 'sm')} Asset</button><button class="dd-item" data-q="license">${icon('key', 'sm')} License</button>
            <button class="dd-item" data-q="contract">${icon('file', 'sm')} Contract</button><button class="dd-item" data-q="person">${icon('users', 'sm')} Person</button>
            <div class="dd-sep"></div><button class="dd-item" data-q="import">${icon('upload', 'sm')} Import CSV</button><button class="dd-item" data-q="agent">${icon('download', 'sm')} Deploy agent</button></div></div>` : ''}
          <a class="icon-btn" href="#/alerts" title="Alerts">${icon('bell')}<span class="dot-count" id="alertBadge2" hidden></span></a>
          <button class="icon-btn" id="themeBtn" title="Toggle dark mode">${icon('moon')}</button>
          <button class="user-btn" id="userBtn" aria-haspopup="true"><span class="avatar">${esc(initials(S.me.name || S.me.username))}</span>
            <span class="who">${esc(S.me.name || S.me.username)}<small>${esc(titleCase(S.me.role === 'tech' ? 'technician' : S.me.role))}</small></span></button>
        </div>
      </header>
      <div class="menu" id="userMenu" hidden>
        <div class="small muted" style="padding:6px 10px">Signed in as <b>${esc(S.me.username)}</b></div><hr>
        <a href="#/security">${icon('shieldCheck')} Security &amp; two-factor</a>
        <button id="kbBtn">${icon('info')} Keyboard shortcuts</button>
        <button id="logout">${icon('logout')} Sign out</button>
      </div>
      <main class="content" id="view"></main>
    </div></div>`;
  $('#logout').onclick = guard(async () => { await api('POST', '/api/logout'); location.hash = ''; S.me = null; renderLogin(); });
  $('#userBtn').onclick = (e) => { e.stopPropagation(); $('#userMenu').hidden = !$('#userMenu').hidden; };
  $('#menuBtn').onclick = () => $('#side').classList.toggle('open');
  $('#collapseBtn').onclick = () => { const c = !$('#app').classList.contains('collapsed'); $('#app').classList.toggle('collapsed', c); prefSet('sideCollapsed', c); };
  $('#palHint').onclick = openPalette;
  $('#kbBtn').onclick = shortcutsHelp;
  if ($('#quickBtn')) {
    $('#quickBtn').onclick = (e) => { e.stopPropagation(); $('#quickMenu').hidden = !$('#quickMenu').hidden; };
    $$('[data-q]').forEach((b) => b.onclick = () => { $('#quickMenu').hidden = true; ({ asset: newAssetModal, license: () => { location.hash = '#/licenses'; setTimeout(() => $('#newLic')?.click(), 350); },
      contract: () => { location.hash = '#/contracts'; setTimeout(() => $('#newC')?.click(), 350); }, person: () => { location.hash = '#/people'; setTimeout(() => $('#newO')?.click(), 350); },
      import: () => { location.hash = '#/import'; }, agent: () => { location.hash = '#/agents'; } })[b.dataset.q](); });
  }
  $('#themeBtn').onclick = () => {
    const cur = document.documentElement.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    const next = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem('theme', next); } catch { /* storage unavailable */ }
  };
  let t;
  const gs = $('#gsearch'), gr = $('#gresults');
  gs.addEventListener('input', () => {
    clearTimeout(t);
    t = setTimeout(guard(async () => {
      if (gs.value.trim().length < 2) { gr.hidden = true; return; }
      const r = await GET(`/api/search?${qs({ q: gs.value.trim() })}`);
      const sec = (title, items, fn) => (items.length ? `<div class="grp">${title}</div>${items.map(fn).join('')}` : '');
      gr.innerHTML = sec('Assets', r.assets, (a) => `<a href="#/assets/${a.id}">${icon(TYPE_ICON[a.type] || 'box', 'sm')} ${esc(a.name)} <span class="muted small">${esc(a.asset_tag)} · ${esc(a.serial || a.ip || '')}</span></a>`)
        + sec('People', r.people, (p) => `<a href="#/people/${p.id}">${icon('users', 'sm')} ${esc(p.name)} <span class="muted small">${esc(p.email || '')}</span></a>`)
        + sec('Software', r.software, (s) => `<a href="#/software/${s.id}">${icon('layers', 'sm')} ${esc(s.name)} <span class="muted small">${esc(s.publisher)}</span></a>`)
        || '<div class="empty">No matches</div>';
      gr.hidden = false;
    }), 220);
  });
  gs.addEventListener('keydown', (e) => { if (e.key === 'Enter') { gr.hidden = true; location.hash = `#/assets?q=${encodeURIComponent(gs.value)}`; } });
  document.addEventListener('click', (e) => {
    if (!e.target.closest('.search')) gr.hidden = true;
    if (!e.target.closest('#userMenu') && $('#userMenu')) $('#userMenu').hidden = true;
  });
  refreshAlertBadge();
}
const refreshAlertBadge = async () => {
  try {
    const al = await api('GET', '/api/alerts', undefined, { background: true });
    for (const id of ['#alertBadge', '#alertBadge2']) { const b = $(id); if (b) { b.textContent = al.length; b.hidden = !al.length; } }
  } catch { /* ignore */ }
};

function renderLogin(msg = '', step = null) {
  $('#root').innerHTML = `<div class="login">
    <section class="login-art">
      <div class="brand"><img src="logo-192.png" alt=""><div><b>Asset Portal</b><small>IT asset management</small></div></div>
      <h2>Every device, every license, always up to date.</h2>
      <ul>
        <li>${icon('check')} Automatic hardware &amp; software inventory from the Windows agent</li>
        <li>${icon('check')} License compliance, contracts, warranties and lifecycle in one place</li>
        <li>${icon('check')} End-to-end encrypted agent channel, two-factor sign-in and full audit trail</li>
      </ul>
    </section>
    <section class="login-form"><form id="loginForm" autocomplete="on">
      <h1>${step ? 'Two-factor verification' : 'Sign in'}</h1>
      <p class="muted" style="margin:0 0 22px">${step ? 'Enter the 6-digit code from your authenticator app.' : 'Use your portal account to continue.'}</p>
      ${msg ? `<div class="login-err" role="alert">${esc(msg)}</div>` : ''}
      ${step ? `<div class="field"><label for="otp">Authentication code</label><input id="otp" name="otp" class="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" required></div>`
        : `<div class="field"><label for="u">Username</label><input id="u" name="username" autocomplete="username" required></div>
           <div class="field"><label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" required></div>`}
      <button class="btn primary">${step ? 'Verify' : 'Sign in'}</button>
      ${step ? '<p style="text-align:center;margin-top:14px"><a href="#" id="backLogin">Use a different account</a></p>' : ''}
    </form></section></div>`;
  ($('#otp') || $('#u')).focus();
  if ($('#backLogin')) $('#backLogin').onclick = (e) => { e.preventDefault(); renderLogin(); };
  $('#loginForm').onsubmit = async (e) => {
    e.preventDefault();
    const body = step ? { ...step, otp: $('#otp').value } : formValues(e.target);
    try {
      const r = await api('POST', '/api/login', body, { noRedirect: true });
      if (r.otp_required) return renderLogin('', body);
      await boot();
    } catch (err) { renderLogin(err.message, step); }
  };
}

// ------------------------------------------------------------------ router
const routes = [];
const route = (re, fn) => routes.push([re, fn]);
let currentRender = null;
async function navigate() {
  if (!S.me) return;
  const [path, query] = (location.hash.slice(1) || '/dashboard').split('?');
  const q = Object.fromEntries(new URLSearchParams(query || ''));
  S.module = moduleOf(path.split('/')[1]);
  $$('.side a').forEach((a) => a.classList.toggle('active', path.split('/')[1] === a.dataset.nav));
  $('#side')?.classList.remove('open');
  const view = $('#view');
  for (const [re, fn] of routes) {
    const m = re.exec(path);
    if (m) {
      view.innerHTML = skeleton();
      currentRender = () => fn(view, q, ...m.slice(1));
      try { await currentRender(); } catch (e) { if (e.message !== 'Not logged in') view.innerHTML = `<div class="card"><h2>Error</h2><p>${esc(e.message)}</p></div>`; }
      window.scrollTo(0, 0);
      return;
    }
  }
  view.innerHTML = '<div class="empty">Page not found</div>';
}
const reload = () => currentRender && currentRender().catch((e) => toast(e.message, true));
window.addEventListener('hashchange', navigate);

const head = (title, actions = '', crumb = '', sub = '') => `${crumb ? `<div class="crumb">${crumb}</div>` : ''}
  <div class="page-head"><div><h1>${title}</h1>${sub ? `<div class="sub">${sub}</div>` : ''}</div><div class="actions">${actions}</div></div>`;

// ------------------------------------------------------------------ dashboard
route(/^\/dashboard$/, async (v) => {
  const d = await GET('/api/dashboard');
  const sev = Object.fromEntries(d.alerts.map((a) => [a.severity, a.n]));
  const kind = { hardware: 'Hardware', software: 'Software', os: 'OS', created: 'New asset', status: 'Status', assignment: 'Assignment', security: 'Security' };
  const pct = d.agents ? Math.round((d.agents_online / d.agents) * 100) : 0;
  const hour = new Date().getHours();
  v.innerHTML = head(`Good ${hour < 12 ? 'morning' : hour < 18 ? 'afternoon' : 'evening'}, ${esc((S.me.name || S.me.username).split(' ')[0])}`,
    can('tech') ? `<a class="btn" href="#/agents">${icon('download', 'sm')} Deploy agent</a><button class="btn primary" id="dNew">${icon('plus', 'sm')} Add asset</button>` : '',
    '', `Here is the state of ${esc(S.me.org_name)}'s IT estate.`) + `
    <div class="kpis">
      <a class="kpi" href="#/assets"><span class="chip">${icon('box')}</span><div><div class="v">${fmtNum(d.assets)}</div><div class="l">Total assets</div></div></a>
      <a class="kpi ${d.low_stock ? 'warn' : ''}" href="#/stock${d.low_stock ? '?low=1' : ''}"><span class="chip">${icon('box')}</span><div><div class="v">${d.stock_items}</div><div class="l">Stock items${d.low_stock ? ` · <b style="color:var(--warn)">${d.low_stock} low</b>` : ''}</div></div></a>
      <a class="kpi ${d.audit_due ? 'warn' : ''}" href="#/reports/audit_due"><span class="chip">${icon('shieldCheck')}</span><div><div class="v">${d.audit_due}</div><div class="l">Audits overdue${d.pending_accept ? ` · ${d.pending_accept} awaiting acceptance` : ''}</div></div></a>
      <a class="kpi ${d.overdue ? 'crit' : ''}" href="#/checkouts${d.overdue ? '?state=overdue' : ''}"><span class="chip">${icon('tag')}</span><div><div class="v">${d.checked_out}</div><div class="l">Checked out${d.overdue ? ` · <b style="color:var(--crit)">${d.overdue} overdue</b>` : ''}</div></div></a>
      <a class="kpi ok" href="#/agents"><span class="chip">${icon('monitor')}</span><div><div class="v">${d.agents_online}<small> / ${d.agents}</small></div><div class="l">Agents online (${pct}%)</div></div></a>
      <a class="kpi ${sev.critical ? 'crit' : 'ok'}" href="#/alerts"><span class="chip">${icon('bell')}</span><div><div class="v">${sev.critical || 0}</div><div class="l">Critical alerts · ${sev.warning || 0} warnings</div></div></a>
      <a class="kpi ${d.licenses.over ? 'crit' : 'ok'}" href="#/licenses"><span class="chip">${icon('key')}</span><div><div class="v">${d.licenses.over}<small> / ${d.licenses.total}</small></div><div class="l">Licenses over-deployed</div></div></a>
      <a class="kpi" href="#/software"><span class="chip">${icon('layers')}</span><div><div class="v">${fmtNum(d.software)}</div><div class="l">Software titles</div></div></a>
      <a class="kpi ${d.warranty_90 ? 'warn' : ''}" href="#/reports/warranty_expiring"><span class="chip">${icon('shield')}</span><div><div class="v">${d.warranty_90}</div><div class="l">Warranties ending ≤ 90 days</div></div></a>
      <a class="kpi ${d.unmanaged ? 'warn' : ''}" href="#/discovery"><span class="chip">${icon('radar')}</span><div><div class="v">${d.unmanaged}</div><div class="l">Unmanaged network devices</div></div></a>
      <a class="kpi" href="#/reports/depreciation"><span class="chip">${icon('dollar')}</span><div><div class="v" style="font-size:20px">${money(d.total_value)}</div><div class="l">Purchase value in service</div></div></a>
    </div>
    <div class="grid g3">
      <div class="card"><div class="card-head"><h2>Assets by type</h2></div>${donut(d.by_type, { center: 'assets', href: (r) => `#/assets?type=${r.k}` })}</div>
      <div class="card"><div class="card-head"><h2>Lifecycle status</h2></div>${donut(d.by_status, { center: 'assets', href: (r) => `#/assets?status=${r.k}` })}</div>
      <div class="card"><div class="card-head"><h2>Operating systems</h2></div>${donut(d.by_os, { label: (r) => r.k, center: 'computers', href: (r) => `#/assets?os=${encodeURIComponent(r.k)}` })}</div>
      <div class="card"><div class="card-head"><h2>Most installed software</h2><a class="actions small" href="#/software">View all</a></div>${bars(d.top_software, { label: (r) => r.name, href: (r) => `#/software/${r.id}` })}</div>
      <div class="card"><div class="card-head"><h2>Manufacturers</h2></div>${bars(d.by_manufacturer)}</div>
      <div class="card"><div class="card-head"><h2>Recent changes</h2><a class="actions small" href="#/reports/hardware_changes">Report</a></div>
        ${d.recent_changes.length ? `<ul class="timeline feed">${d.recent_changes.slice(0, 8).map((h) => `<li>
          <div><a href="#/assets/${h.asset_id}" class="cell-main">${esc(h.asset_name)}</a> <span class="pill plain">${kind[h.kind] || h.kind}</span> <span class="muted small" style="float:right">${ago(h.ts)}</span></div>
          <div class="small">${historyText(h)}</div></li>`).join('')}</ul>` : '<div class="empty">No changes yet</div>'}</div>
    </div>`;
  if ($('#dNew')) $('#dNew').onclick = newAssetModal;
});

function historyText(h) {
  if (h.kind === 'software') {
    if (h.field === 'installed') return `Installed <b>${esc(h.new_value)}</b>`;
    if (h.field === 'uninstalled') return `Uninstalled <b>${esc(h.new_value)} ${esc(h.old_value || '')}</b>`;
    return `Updated ${esc(h.old_value)} → <b>${esc(h.new_value)}</b>`;
  }
  if (h.field && (h.old_value !== null || h.new_value !== null) && !['note', 'maintenance', 'created', 'agent'].includes(h.kind)) {
    return `${esc(titleCase(h.field))}: <span class="muted">${esc(h.old_value ?? '—')}</span> → <b>${esc(h.new_value ?? '—')}</b>`;
  }
  return esc(h.new_value);
}

// ------------------------------------------------------------------ assets list
const ASSET_FORM = () => [
  { name: 'name', label: 'Name', required: true },
  { name: 'asset_tag', label: 'Asset tag', placeholder: 'auto-generated if empty' },
  { name: 'type', label: 'Type', type: 'select', options: opts(S.meta.types), blank: false },
  { name: 'status', label: 'Status', type: 'select', options: opts(S.meta.statuses), blank: false },
  { name: 'model_id', label: 'Model (from catalog)', type: 'select', options: S.meta.models.map((m) => ({ value: m.id, label: [m.manufacturer, m.name, m.model_number].filter(Boolean).join(' · ') })), help: 'Sets manufacturer and model automatically.' },
  { name: 'company_id', label: 'Company', type: 'select', options: opts(S.meta.companies) },
  { name: 'manufacturer', label: 'Manufacturer (if no model)' }, { name: 'model', label: 'Model (if no model)' },
  { name: 'serial', label: 'Serial number' }, { name: 'hostname', label: 'Hostname' },
  { name: 'ip', label: 'IP address' }, { name: 'mac', label: 'MAC address' },
  { name: 'person_id', label: 'Assigned to', type: 'select', options: opts(S.meta.people) },
  { name: 'location_id', label: 'Location', type: 'select', options: opts(S.meta.locations) },
  { name: 'department_id', label: 'Department', type: 'select', options: opts(S.meta.departments) },
  { name: 'supplier_id', label: 'Supplier', type: 'select', options: opts(S.meta.suppliers) },
  { name: 'purchase_date', label: 'Purchase date', type: 'date' }, { name: 'purchase_cost', label: 'Purchase cost', type: 'number' },
  { name: 'order_number', label: 'Order / invoice #' }, { name: 'warranty_end', label: 'Warranty end', type: 'date' },
  { name: 'eol_date', label: 'Planned replacement (EOL)', type: 'date' },
  ...S.meta.custom_fields.map((cf) => ({ name: `cf_${cf.id}`, label: cf.name, type: cf.field_type === 'number' ? 'number' : cf.field_type === 'date' ? 'date' : 'text' })),
  { name: 'notes', label: 'Notes', type: 'textarea', full: true },
];
function assetFormSubmit(vals, existingCustom = {}) {
  const custom = { ...existingCustom };
  for (const cf of S.meta.custom_fields) { const v = vals[`cf_${cf.id}`]; delete vals[`cf_${cf.id}`]; if (v) custom[cf.name] = v; else delete custom[cf.name]; }
  vals.custom_json = Object.keys(custom).length ? custom : null;
  return vals;
}
function newAssetModal() {
  formModal({
    title: 'Add asset', fields: ASSET_FORM(), values: { type: 'workstation', status: 'in_stock' },
    onSubmit: async (vals) => { const r = await api('POST', '/api/assets', assetFormSubmit(vals)); toast('Asset created'); location.hash = `#/assets/${r.id}`; },
  });
}

route(/^\/assets$/, async (v, q) => {
  const st = { q: q.q || '', type: q.type || '', status: q.status || '', location_id: q.location_id || '', department_id: q.department_id || '',
    agent: q.agent || '', os: q.os || '', software_id: q.software_id || '', company_id: q.company_id || '', model_id: q.model_id || '', category_id: q.category_id || '', supplier_id: q.supplier_id || '', sort: q.sort || 'name', dir: q.dir || 'asc', page: Number(q.page) || 1, limit: 50 };
  const selected = new Set();
  v.innerHTML = head('Assets', `${can('tech') ? `<button class="btn" id="importBtn">${icon('upload', 'sm')} Import</button>` : ''}
    <button class="btn" id="exportBtn">${icon('download', 'sm')} Export</button>${can('tech') ? `<button class="btn primary" id="newBtn">${icon('plus', 'sm')} Add asset</button>` : ''}`, '', 'Hardware and devices across the organization.') + `
    <div class="filters">
      <input type="search" id="fq" placeholder="Search name, tag, serial, IP, user…" value="${esc(st.q)}">
      <select id="ftype"><option value="">All types</option>${S.meta.types.map((t) => `<option value="${t}" ${st.type === t ? 'selected' : ''}>${titleCase(t)}</option>`).join('')}</select>
      <select id="fstatus"><option value="">All statuses</option>${S.meta.statuses.map((t) => `<option value="${t}" ${st.status === t ? 'selected' : ''}>${titleCase(t)}</option>`).join('')}</select>
      <select id="floc"><option value="">All locations</option>${S.meta.locations.map((l) => `<option value="${l.id}" ${String(st.location_id) === String(l.id) ? 'selected' : ''}>${esc(l.name)}</option>`).join('')}</select>
      <select id="fdept"><option value="">All departments</option>${S.meta.departments.map((l) => `<option value="${l.id}" ${String(st.department_id) === String(l.id) ? 'selected' : ''}>${esc(l.name)}</option>`).join('')}</select>
      <select id="fagent"><option value="">Any agent state</option><option value="online" ${st.agent === 'online' ? 'selected' : ''}>Agent online</option>
        <option value="offline" ${st.agent === 'offline' ? 'selected' : ''}>Agent offline</option><option value="none" ${st.agent === 'none' ? 'selected' : ''}>No agent</option></select>
      ${st.os ? `<span class="pill info">OS: ${esc(st.os)}</span>` : ''}${['company_id', 'model_id', 'category_id', 'supplier_id'].filter((k) => st[k]).map((k) => `<a class="pill info" href="#/assets" title="Clear filter">${titleCase(k.replace('_id', ''))} filter ✕</a>`).join('')}${st.software_id ? '<span class="pill info">Filtered by software</span>' : ''}
      <span style="margin-left:auto"></span>
      <div class="dd"><button class="btn" id="viewsBtn">${icon('list', 'sm')} Views</button><div class="dd-menu" id="viewsMenu" hidden></div></div>
      <div class="dd"><button class="btn" id="colsBtn">${icon('settings', 'sm')} Columns</button><div class="dd-menu" id="colsMenu" hidden></div></div>
    </div>
    <div class="bulkbar" id="bulk" hidden></div>
    <div id="list"></div>`;
  let visibleCols = prefGet('assetCols', DEFAULT_ASSET_COLS);
  const renderColsMenu = () => {
    $('#colsMenu').innerHTML = `<div class="dd-title">Show columns</div>${assetColumns().map((c) => `<label class="dd-item"><input type="checkbox" data-col="${c.key}" ${visibleCols.includes(c.key) ? 'checked' : ''}> ${c.label}</label>`).join('')}
      <div class="dd-sep"></div><button class="dd-item" id="colsReset">Reset to default</button>`;
    $$('[data-col]').forEach((cb) => cb.onchange = () => {
      visibleCols = assetColumns().map((c) => c.key).filter((k) => (k === cb.dataset.col ? cb.checked : visibleCols.includes(k)));
      prefSet('assetCols', visibleCols); load();
    });
    $('#colsReset').onclick = () => { visibleCols = DEFAULT_ASSET_COLS; prefSet('assetCols', visibleCols); renderColsMenu(); load(); };
  };
  const FILTER_KEYS = ['q', 'type', 'status', 'location_id', 'department_id', 'agent', 'os', 'sort', 'dir'];
  const renderViewsMenu = () => {
    const views = prefGet('assetViews', []);
    $('#viewsMenu').innerHTML = `<div class="dd-title">Saved views</div>
      ${views.length ? views.map((vw, i) => `<div class="dd-row"><button class="dd-item" data-view="${i}">${esc(vw.name)}</button><button class="icon-btn" data-delview="${i}" title="Delete view">${icon('x', 'sm')}</button></div>`).join('') : '<div class="dd-item muted">No saved views yet</div>'}
      <div class="dd-sep"></div><button class="dd-item" id="saveView">${icon('plus', 'sm')} Save current filters…</button>`;
    $$('[data-view]').forEach((b) => b.onclick = () => { const vw = views[b.dataset.view]; location.hash = `#/assets?${qs(vw.filters)}`; });
    $$('[data-delview]').forEach((b) => b.onclick = (e) => { e.stopPropagation(); views.splice(Number(b.dataset.delview), 1); prefSet('assetViews', views); renderViewsMenu(); });
    $('#saveView').onclick = () => formModal({ title: 'Save view', fields: [{ name: 'name', label: 'View name', required: true, full: true, placeholder: 'e.g. Laptops in stock' }],
      onSubmit: async (val) => { views.push({ name: val.name, filters: Object.fromEntries(FILTER_KEYS.map((k) => [k, st[k]]).filter(([, x]) => x)) }); prefSet('assetViews', views); toast('View saved'); } });
  };
  for (const [btn, menu, fill] of [['#colsBtn', '#colsMenu', renderColsMenu], ['#viewsBtn', '#viewsMenu', renderViewsMenu]]) {
    $(btn).onclick = (e) => { e.stopPropagation(); const m = $(menu); const open = m.hidden; $$('.dd-menu').forEach((x) => { x.hidden = true; }); if (open) { fill(); m.hidden = false; placeMenu(m); } };
  }
  const load = guard(async () => {
    const data = await GET(`/api/assets?${qs(st)}`);
    const cols = assetColumns().filter((c) => visibleCols.includes(c.key));
    const arrow = (k) => (st.sort === k ? (st.dir === 'asc' ? ' ▲' : ' ▼') : '');
    const pages = Math.max(1, Math.ceil(data.total / st.limit));
    $('#list').innerHTML = !data.rows.length ? `<div class="table-wrap"><div class="empty">${icon('monitor')}<div>No assets match these filters.</div><div class="small">Install the agent on a Windows PC or add assets manually.</div></div></div>` : `
      <div class="table-wrap"><table><thead><tr>${can('tech') ? '<th style="width:30px"><input type="checkbox" id="selAll" aria-label="Select all"></th>' : ''}
        ${cols.map((c) => `<th class="${c.sort ? 'sortable' : ''} ${c.num ? 'num' : ''}" ${c.sort ? `data-sort="${c.sort}"` : ''}>${c.label}${c.sort ? arrow(c.sort) : ''}</th>`).join('')}</tr></thead><tbody>
        ${data.rows.map((a) => `<tr>${can('tech') ? `<td><input type="checkbox" class="sel" value="${a.id}" ${selected.has(a.id) ? 'checked' : ''} aria-label="Select"></td>` : ''}
          ${cols.map((c) => `<td class="${c.num ? 'num' : ''}">${c.render(a)}</td>`).join('')}</tr>`).join('')}
      </tbody></table></div>
      <div class="filters" style="margin-top:10px"><span class="muted">${fmtNum(data.total)} assets</span><span style="margin-left:auto"></span>
        <button class="btn sm" id="prev" ${st.page <= 1 ? 'disabled' : ''}>‹ Prev</button><span class="small">Page ${st.page} / ${pages}</span>
        <button class="btn sm" id="next" ${st.page >= pages ? 'disabled' : ''}>Next ›</button></div>`;
    $$('th[data-sort]').forEach((th) => th.onclick = () => { const k = th.dataset.sort; st.dir = st.sort === k && st.dir === 'asc' ? 'desc' : 'asc'; st.sort = k; load(); });
    if ($('#prev')) { $('#prev').onclick = () => { st.page--; load(); }; $('#next').onclick = () => { st.page++; load(); }; }
    $$('.sel').forEach((c) => c.onchange = () => { c.checked ? selected.add(Number(c.value)) : selected.delete(Number(c.value)); renderBulk(); });
    if ($('#selAll')) $('#selAll').onchange = (e) => { $$('.sel').forEach((c) => { c.checked = e.target.checked; c.onchange(); }); };
  });
  const renderBulk = () => {
    const b = $('#bulk');
    b.hidden = !selected.size;
    if (!selected.size) return;
    b.innerHTML = `<b>${selected.size} selected</b>
      <select id="bStatus"><option value="">Set status…</option>${S.meta.statuses.map((s) => `<option value="${s}">${titleCase(s)}</option>`).join('')}</select>
      <select id="bLoc"><option value="">Set location…</option>${S.meta.locations.map((l) => `<option value="${l.id}">${esc(l.name)}</option>`).join('')}</select>
      <select id="bDept"><option value="">Set department…</option>${S.meta.departments.map((l) => `<option value="${l.id}">${esc(l.name)}</option>`).join('')}</select>
      <select id="bPerson"><option value="">Assign to…</option>${S.meta.people.map((l) => `<option value="${l.id}">${esc(l.name)}</option>`).join('')}</select>
      ${hasPerm('assets.checkout') ? '<button class="btn sm" id="bCo">Check out…</button>' : ''}${hasPerm('assets.audit') ? '<button class="btn sm" id="bAudit">Audit…</button>' : ''}
      <button class="btn sm" id="bScan">Refresh inventory</button><button class="btn sm" id="bLabels">Print labels</button>
      <button class="btn sm danger" id="bDel">Delete</button><button class="btn sm" id="bClear">Clear</button>`;
    const apply = (field) => guard(async (e) => {
      if (!e.target.value) return;
      await api('POST', '/api/assets/bulk', { ids: [...selected], action: 'update', changes: { [field]: e.target.value } });
      toast(`Updated ${selected.size} assets`); await refreshMeta(); load();
    });
    $('#bStatus').onchange = apply('status'); $('#bLoc').onchange = apply('location_id'); $('#bDept').onchange = apply('department_id'); $('#bPerson').onchange = apply('person_id');
    if ($('#bCo')) $('#bCo').onclick = () => checkoutModal({ name: `${selected.size} assets`, ids: [...selected] });
    if ($('#bAudit')) $('#bAudit').onclick = () => auditModal({ ids: [...selected] });
    $('#bScan').onclick = guard(async () => { await api('POST', '/api/assets/bulk', { ids: [...selected], action: 'scan' }); toast('Agents will re-scan within a minute'); });
    $('#bLabels').onclick = () => { location.hash = `#/labels?ids=${[...selected].join(',')}`; };
    $('#bDel').onclick = guard(async () => {
      if (!(await confirmBox(`Delete ${selected.size} assets permanently? Their agents will re-enroll on next check-in.`))) return;
      await api('POST', '/api/assets/bulk', { ids: [...selected], action: 'delete' }); selected.clear(); renderBulk(); load();
    });
    $('#bClear').onclick = () => { selected.clear(); renderBulk(); load(); };
  };
  let t;
  $('#fq').oninput = (e) => { clearTimeout(t); t = setTimeout(() => { st.q = e.target.value; st.page = 1; load(); }, 250); };
  [['#ftype', 'type'], ['#fstatus', 'status'], ['#floc', 'location_id'], ['#fdept', 'department_id'], ['#fagent', 'agent']]
    .forEach(([sel, k]) => { $(sel).onchange = (e) => { st[k] = e.target.value; st.page = 1; load(); }; });
  $('#exportBtn').onclick = () => { location.href = `/api/assets/export?${qs({ ...st, page: '', limit: '' })}`; };
  if ($('#newBtn')) $('#newBtn').onclick = newAssetModal;
  if ($('#importBtn')) $('#importBtn').onclick = importModal;
  load();
});

/** Imports now live in the import centre (stored files, field mapping, dry run). */
function importModal() { location.hash = '#/import'; }

// ------------------------------------------------------------------ asset detail
route(/^\/assets\/(\d+)$/, async (v, q, id) => {
  const a = await GET(`/api/assets/${id}`);
  const hw = a.hardware || {};
  const tab = q.tab || 'overview';
  const kvs = (pairs) => `<dl class="kv">${pairs.filter(([, val]) => val !== null && val !== undefined && val !== '').map(([k, val]) => `<dt>${k}</dt><dd>${val}</dd>`).join('')}</dl>`;
  const tabs = [['overview', 'Overview'], ['hardware', 'Hardware'], ['software', `Software (${a.software.length})`], ['updates', `Patches (${a.updates.length})`],
    ...(a.agent && can('tech') ? [['activity', 'Activity']] : []),
    ['history', 'History'], ['contracts', `Contracts (${a.contracts.length})`], ['relations', `Relations (${a.relations.length})`]];
  v.innerHTML = head(`<span class="asset-hero"><span class="chip">${icon(TYPE_ICON[a.type] || 'box')}</span><span>${esc(a.name)} ${pill(a.status)}<div class="sub">${esc(titleCase(a.type))} · ${esc([a.manufacturer, a.model].filter(Boolean).join(' ') || 'No model')} · <span class="mono">${esc(a.asset_tag)}</span></div></span></span>`,
    `${a.agent && can('tech') ? `<button class="btn" id="scanBtn">${icon('refresh', 'sm')} Refresh inventory</button>` : ''}
     ${hasPerm('assets.audit') ? `<button class="btn" id="auditBtn">${icon('shieldCheck', 'sm')} Audit</button>` : ''}
     ${hasPerm('assets.checkout') ? (a.checkout ? `<button class="btn" id="ciBtn">${icon('tag', 'sm')} Check in</button>` : `<button class="btn" id="coBtn">${icon('tag', 'sm')} Check out</button>`) : ''}
     <a class="btn" href="#/labels?ids=${a.id}">${icon('print', 'sm')} Label</a>
     ${can('tech') ? `<button class="btn" id="noteBtn">${icon('plus', 'sm')} Note</button><button class="btn primary" id="editBtn">Edit</button><button class="btn danger" id="delBtn">Delete</button>` : ''}`,
    `<a href="#/assets">Assets</a> / <span class="mono">${esc(a.asset_tag)}</span>`)
    + (a.checkout ? callout(a.checkout.due_at && a.checkout.due_at < new Date().toISOString().slice(0, 10) ? 'crit' : 'info',
      `Checked out to <b>${esc(a.checkout.person || (a.checkout.location ? `📍 ${a.checkout.location}` : '—'))}</b>${a.checkout.accept_status ? ' ' + pill(a.checkout.accept_status === 'accepted' ? 'ok' : a.checkout.accept_status === 'declined' ? 'crit' : 'warn', a.checkout.accept_status === 'pending' ? 'Awaiting acceptance' : titleCase(a.checkout.accept_status)) : ''} since ${fmtDate(a.checkout.out_at)}${a.checkout.due_at ? ` · due back <b>${esc(a.checkout.due_at)}</b>` : ''}${a.checkout.out_notes ? ` · ${esc(a.checkout.out_notes)}` : ''}`, 'tag') : '')
    + (a.alerts.length ? `<div class="callout warn">${icon('alert')}<div>${a.alerts.map((al) => `<div>${pill(al.severity)} ${esc(al.message)}</div>`).join('')}</div></div>` : '')
    + `<div class="tabs">${tabs.map(([k, l]) => `<button data-tab="${k}" class="${tab === k ? 'active' : ''}">${l}</button>`).join('')}</div><div id="tabBody"></div>`;
  $$('.tabs button').forEach((b) => b.onclick = () => { location.hash = `#/assets/${id}?tab=${b.dataset.tab}`; });

  const body = $('#tabBody');
  if (tab === 'overview') {
    const custom = Object.entries(a.custom || {});
    body.innerHTML = `<div class="grid g2">
      <div class="card"><h2>Identity</h2>${kvs([['Asset tag', `<span class="mono">${esc(a.asset_tag)}</span>`], ['Type', titleCase(a.type)], ['Status', pill(a.status)],
        ['Source', titleCase(a.source)], ['Company', a.company_id ? `<a href="#/assets?company_id=${a.company_id}">${esc(a.company)}</a>` : ''],
        ['Manufacturer', esc(a.manufacturer)], ['Model', a.model_id ? `<a href="#/assets?model_id=${a.model_id}">${esc(a.model)}</a>` : esc(a.model)], ['Model number', esc(a.model_number)], ['Category', esc(a.category)],
        ['Supplier', esc(a.supplier || a.vendor)], ['Serial', `<span class="mono">${esc(a.serial)}</span>`],
        ['Hostname', esc(a.hostname)], ['Domain', esc(a.domain)], ['IP address', `<span class="mono">${esc(a.ip)}</span>`], ['MAC', `<span class="mono">${esc(a.mac)}</span>`]])}</div>
      <div class="card"><h2>Ownership & lifecycle</h2>${kvs([
        ['Assigned to', a.person_id ? `<a href="#/people/${a.person_id}">${esc(a.person)}</a>` : '<span class="muted">Unassigned</span>'],
        ['Last logged-on user', esc(a.last_user)], ['Location', esc(a.location)], ['Department', esc(a.department)],
        ['Last audit', a.last_audit_at ? fmtDate(a.last_audit_at) : '<span class="muted">Never</span>'], ['Next audit', a.next_audit_date ? `${esc(a.next_audit_date)}${a.next_audit_date < new Date().toISOString().slice(0, 10) ? ' ' + pill('warn', 'Overdue') : ''}` : ''],
        ['Vendor', esc(a.vendor)], ['Purchase date', esc(a.purchase_date)], ['Purchase cost', money(a.purchase_cost)], ['Order #', esc(a.order_number)],
        ['Warranty end', a.warranty_end ? `${esc(a.warranty_end)} ${a.warranty_end < new Date().toISOString().slice(0, 10) ? pill('expired', 'Expired') : ''}` : ''],
        ['Planned replacement', esc(a.eol_date)], ['Created', fmtDT(a.created_at)], ['Updated', fmtDT(a.updated_at)],
        ...custom.map(([k, val]) => [esc(k), esc(val)])])}
        ${a.notes ? `<h3>Notes</h3><p style="white-space:pre-wrap">${esc(a.notes)}</p>` : ''}</div>
      ${a.os_name || a.cpu ? `<div class="card"><h2>System summary</h2>${kvs([['Operating system', esc(a.os_name)], ['Version / build', esc([a.os_version, a.os_build].filter(Boolean).join(' · '))],
        ['Architecture', esc(a.os_arch)], ['Processor', esc(a.cpu)], ['Cores', esc(a.cpu_cores)], ['Memory', gbFromMb(a.ram_mb)],
        ['Storage', a.disk_total_gb ? `${fmtNum(a.disk_free_gb, 1)} GB free of ${fmtNum(a.disk_total_gb, 1)} GB` : ''],
        ['Last boot', fmtDT(a.last_boot)], ['Antivirus', esc(a.antivirus)], ['Disk encryption', esc(a.encryption)]])}</div>` : ''}
      ${a.agent ? `<div class="card"><h2>Agent</h2>${kvs([['State', `<span class="dot ${a.agent.online ? 'on' : ''}"></span>${a.agent.online ? 'Online' : 'Offline'}`],
        ['Version', esc(a.agent.version)], ['Last heartbeat', `${fmtDT(a.agent.last_heartbeat)} (${ago(a.agent.last_heartbeat)})`],
        ['Last full inventory', `${fmtDT(a.agent.last_checkin)} (${ago(a.agent.last_checkin)})`], ['Reporting from', `<span class="mono">${esc(a.agent.last_ip)}</span>`],
        ['Enrolled', fmtDT(a.agent.enrolled_at)], ['Rescan requested', a.agent.scan_requested ? 'Yes — pending' : '']])}</div>` : ''}
    </div>`;
  } else if (tab === 'hardware') {
    const list = (arr, cols) => (arr?.length ? table(cols, arr) : '<p class="muted">Not reported</p>');
    body.innerHTML = `<div class="grid g2">
      <div class="card"><h2>Processor & board</h2>${kvs([['CPU', esc(hw.cpu?.name || a.cpu)], ['Sockets', esc(hw.cpu?.sockets)], ['Cores / threads', hw.cpu ? `${esc(hw.cpu.cores)} / ${esc(hw.cpu.logical)}` : ''],
        ['Max clock', hw.cpu?.speed_mhz ? `${hw.cpu.speed_mhz} MHz` : ''], ['Chassis', titleCase(hw.chassis)], ['Board', esc([hw.motherboard?.manufacturer, hw.motherboard?.product].filter(Boolean).join(' '))],
        ['Board serial', esc(hw.motherboard?.serial)], ['BIOS', esc([hw.bios?.vendor, hw.bios?.version].filter(Boolean).join(' '))], ['BIOS date', esc(hw.bios?.date)],
        ['System UUID', `<span class="mono small">${esc(hw.uuid)}</span>`], ['TPM', hw.tpm ? `${hw.tpm.enabled ? 'Enabled' : 'Disabled'}${hw.tpm.spec ? ` · spec ${esc(String(hw.tpm.spec).split(',')[0])}` : ''}` : '']])}</div>
      <div class="card"><h2>Memory · ${gbFromMb(a.ram_mb)}</h2>${list(hw.memory_modules, [{ key: 'slot' }, { key: 'capacity_mb', label: 'Size', render: (m) => gbFromMb(m.capacity_mb) }, { key: 'speed', label: 'MHz', num: true }, { key: 'manufacturer' }, { key: 'part_number', label: 'Part #' }])}</div>
      <div class="card"><h2>Volumes</h2>${list(a.disks, [{ key: 'name', label: 'Drive' }, { key: 'label' }, { key: 'fs', label: 'FS' }, { key: 'size_gb', label: 'Size GB', num: true },
        { key: 'free_gb', label: 'Free GB', num: true }, { key: 'u', label: 'Used', render: (d) => usageBar(d.size_gb - d.free_gb, d.size_gb, true) }])}</div>
      <div class="card"><h2>Physical disks</h2>${list(hw.physical_disks, [{ key: 'model' }, { key: 'media', label: 'Type' }, { key: 'size_gb', label: 'Size GB', num: true }, { key: 'serial', render: (d) => `<span class="mono small">${esc(d.serial)}</span>` }])}</div>
      <div class="card"><h2>Graphics</h2>${list(hw.gpus, [{ key: 'name' }, { key: 'driver' }, { key: 'ram_mb', label: 'VRAM', render: (g) => gbFromMb(g.ram_mb) }])}</div>
      <div class="card"><h2>Monitors</h2>${list(hw.monitors, [{ key: 'manufacturer' }, { key: 'model' }, { key: 'serial' }])}</div>
      <div class="card full" style="grid-column:1/-1"><h2>Network adapters</h2>${list(a.nics, [{ key: 'name' }, { key: 'mac', render: (n) => `<span class="mono">${esc(n.mac)}</span>` },
        { key: 'ip', label: 'IP', render: (n) => `<span class="mono small">${esc(n.ip)}</span>` }, { key: 'gateway' }, { key: 'dns', label: 'DNS' }, { key: 'dhcp', label: 'DHCP', render: (n) => (n.dhcp ? 'Yes' : 'No') }])}</div>
    </div>`;
  } else if (tab === 'software') {
    const render = (f) => table([{ key: 'name', render: (s) => `<a href="#/software/${s.id}">${esc(s.name)}</a>` }, { key: 'version' }, { key: 'publisher' },
      { key: 'install_date', label: 'Installed' }, { key: 'status', render: (s) => (s.status !== 'neutral' ? pill(s.status) : '') }],
    a.software.filter((s) => !f || `${s.name} ${s.publisher}`.toLowerCase().includes(f)), { empty: 'No software reported' });
    body.innerHTML = `<div class="filters"><input type="search" id="swf" placeholder="Filter software…"></div><div id="swl">${render('')}</div>`;
    $('#swf').oninput = (e) => { $('#swl').innerHTML = render(e.target.value.toLowerCase()); };
  } else if (tab === 'updates') {
    body.innerHTML = table([{ key: 'hotfix_id', label: 'KB / Hotfix' }, { key: 'description' }, { key: 'installed_on', label: 'Installed' }], a.updates, { empty: 'No patches reported' });
  } else if (tab === 'activity') {
    await renderActivityTab(body, id, q);
  } else if (tab === 'history') {
    body.innerHTML = a.history.length ? `<div class="card"><ul class="timeline">${a.history.map((h) => `<li><span class="muted small">${fmtDT(h.ts)}</span>
      <span><span class="pill ${h.kind === 'maintenance' ? 'warn' : h.kind === 'software' ? 'info' : ''}">${titleCase(h.kind)}</span></span>
      <span>${historyText(h)} <span class="muted small">· ${esc(h.actor)}</span></span></li>`).join('')}</ul></div>` : '<div class="empty">No history</div>';
  } else if (tab === 'contracts') {
    body.innerHTML = table([{ key: 'name', render: (c) => `<a href="#/contracts/${c.id}">${esc(c.name)}</a>` }, { key: 'contract_type', label: 'Type', render: (c) => titleCase(c.contract_type) },
      { key: 'vendor' }, { key: 'start_date', label: 'Start' }, { key: 'end_date', label: 'End' }], a.contracts, { empty: 'Not covered by any contract. Link assets from a contract page.' });
  } else if (tab === 'relations') {
    body.innerHTML = `${can('tech') ? `<div class="filters"><button class="btn" id="addRel">${icon('plus', 'sm')} Add relation</button></div>` : ''}
      ${table([{ key: 'rel_type', label: 'Relationship', render: (r) => (r.dir === 'out' ? `This ${titleCase(r.rel_type).toLowerCase()}` : `${titleCase(r.rel_type)} this`) },
        { key: 'other_name', label: 'Asset', render: (r) => `<a href="#/assets/${r.other_id}">${esc(r.other_name)}</a> <span class="muted small">${esc(r.other_tag)}</span>` },
        { key: 'other_type', label: 'Type', render: (r) => titleCase(r.other_type) },
        ...(can('tech') ? [{ key: 'x', label: '', render: (r) => `<button class="btn sm danger" data-delrel="${r.id}">Remove</button>` }] : [])], a.relations,
      { empty: 'No relationships. Link this asset to monitors, docking stations, switches or servers it depends on.' })}`;
    $$('[data-delrel]').forEach((b) => b.onclick = guard(async () => { await api('DELETE', `/api/relations/${b.dataset.delrel}`); reload(); }));
    if ($('#addRel')) $('#addRel').onclick = () => assetPicker({
      title: 'Add relation', extra: fieldHtml({ name: 'rel_type', label: 'Relationship', type: 'select', blank: false,
        options: opts(['connected_to', 'depends_on', 'hosts', 'installed_in', 'component_of', 'backup_of']) }),
      single: true, onPick: async (ids, form) => { await api('POST', `/api/assets/${id}/relations`, { to_asset: ids[0], rel_type: form.rel_type.value }); reload(); },
    });
  }

  if ($('#coBtn')) $('#coBtn').onclick = () => checkoutModal(a);
  if ($('#auditBtn')) $('#auditBtn').onclick = () => auditModal(a);
  if ($('#ciBtn')) $('#ciBtn').onclick = () => checkinModal(a);
  if ($('#editBtn')) $('#editBtn').onclick = () => {
    const vals = { ...a };
    for (const cf of S.meta.custom_fields) vals[`cf_${cf.id}`] = a.custom?.[cf.name];
    formModal({ title: `Edit ${a.name}`, fields: ASSET_FORM(), values: vals,
      onSubmit: async (val) => { await api('PUT', `/api/assets/${id}`, assetFormSubmit(val, a.custom)); toast('Saved'); reload(); } });
  };
  if ($('#delBtn')) $('#delBtn').onclick = guard(async () => {
    if (!(await confirmBox(`Delete ${a.name}? ${a.agent ? 'Its agent will re-register it on the next check-in unless you uninstall the agent.' : ''}`))) return;
    await api('DELETE', `/api/assets/${id}`); toast('Asset deleted'); location.hash = '#/assets';
  });
  if ($('#scanBtn')) $('#scanBtn').onclick = guard(async () => { await api('POST', `/api/assets/${id}/scan`); toast('The agent will send fresh inventory within about a minute'); });
  if ($('#noteBtn')) $('#noteBtn').onclick = () => formModal({
    title: 'Add note or maintenance record',
    fields: [{ name: 'kind', label: 'Type', type: 'select', blank: false, options: [{ value: 'note', label: 'Note' }, { value: 'maintenance', label: 'Maintenance / repair' }], full: true },
      { name: 'text', label: 'Details', type: 'textarea', required: true, full: true }],
    onSubmit: async (val) => { await api('POST', `/api/assets/${id}/notes`, val); location.hash = `#/assets/${id}?tab=history`; reload(); },
  });
});

function assetPicker({ title, onPick, single = false, extra = '' }) {
  const m = modal({
    title, submitLabel: single ? 'Add' : 'Link selected',
    body: `${extra}<div class="field" style="margin:12px 0"><label for="pk">Find asset</label><input id="pk" type="search" placeholder="Name, tag, serial…"></div><div id="pkres"></div>`,
    onSubmit: async (form) => {
      const ids = $$('input[name=pick]:checked', form).map((c) => Number(c.value));
      if (!ids.length) throw new Error('Select an asset');
      await onPick(ids, form);
    },
  });
  const load = guard(async (q) => {
    const r = await GET(`/api/assets?${qs({ q, limit: 30 })}`);
    $('#pkres', m).innerHTML = r.rows.map((a) => `<label style="display:flex;gap:8px;padding:4px 0"><input type="${single ? 'radio' : 'checkbox'}" name="pick" value="${a.id}">
      ${esc(a.name)} <span class="muted small">${esc(a.asset_tag)} · ${titleCase(a.type)}</span></label>`).join('') || '<p class="muted">No matches</p>';
  });
  let t;
  $('#pk', m).oninput = (e) => { clearTimeout(t); t = setTimeout(() => load(e.target.value), 250); };
  load('');
}

// ------------------------------------------------------------------ labels
route(/^\/labels$/, async (v, q) => {
  const r = await GET(`/api/assets?${qs({ ids: q.ids, limit: 1000 })}`);
  v.innerHTML = head('Asset labels', `<button class="btn primary" data-print>${icon('print', 'sm')} Print</button>`) + `<p class="muted no-print">QR codes link to the asset page in this portal.</p>
    <div class="labels">${r.rows.map((a) => `<div class="label"><div class="qr" data-url="${esc(`${location.origin}/#/assets/${a.id}`)}"></div>
      <div><b>${esc(a.asset_tag)}</b><div>${esc(a.name)}</div><div style="font-size:11px">${esc(a.serial ? `S/N ${a.serial}` : '')}</div><div style="font-size:11px">${esc(S.me.org_name)}</div></div></div>`).join('')}</div>`;
  try {
    if (!window.QRCode) await new Promise((res, rej) => { const s = document.createElement('script'); s.src = 'https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js'; s.onload = res; s.onerror = rej; setTimeout(rej, 5000); document.head.appendChild(s); });
    $$('.qr').forEach((el) => new window.QRCode(el, { text: el.dataset.url, width: 84, height: 84, correctLevel: window.QRCode.CorrectLevel.M }));
  } catch { $$('.qr').forEach((el) => { el.textContent = 'QR unavailable offline'; el.style.fontSize = '10px'; }); }
});

// ------------------------------------------------------------------ software
route(/^\/software$/, async (v, q) => {
  const st = { q: q.q || '', status: q.status || '', sort: 'installs', page: 1, limit: 100 };
  v.innerHTML = head('Software catalog') + `<div class="filters">
    <input type="search" id="sq" placeholder="Search software or publisher…" value="${esc(st.q)}">
    <select id="ss"><option value="">All</option><option value="authorized">Authorized</option><option value="prohibited">Prohibited</option><option value="neutral">Unclassified</option></select>
    <span class="muted small">Mark titles as <b>prohibited</b> to raise alerts wherever they are installed.</span></div><div id="sl"></div>`;
  const load = guard(async () => {
    const r = await GET(`/api/software?${qs(st)}`);
    const pages = Math.max(1, Math.ceil(r.total / st.limit));
    $('#sl').innerHTML = table([
      { key: 'name', render: (s) => `<a href="#/software/${s.id}">${esc(s.name)}</a>` }, { key: 'publisher' }, { key: 'category' },
      { key: 'installs', num: true, render: (s) => (s.installs ? `<a href="#/assets?software_id=${s.id}">${s.installs}</a>` : '0') },
      { key: 'versions', num: true }, { key: 'status', render: (s) => pill(s.status, s.status === 'neutral' ? 'Unclassified' : null) },
    ], r.rows, { empty: 'No software inventoried yet' }) + `<div class="filters" style="margin-top:10px"><span class="muted">${fmtNum(r.total)} titles</span><span style="margin-left:auto"></span>
      <button class="btn sm" id="sp" ${st.page <= 1 ? 'disabled' : ''}>‹ Prev</button><span class="small">Page ${st.page} / ${pages}</span><button class="btn sm" id="sn" ${st.page >= pages ? 'disabled' : ''}>Next ›</button></div>`;
    $('#sp').onclick = () => { st.page--; load(); }; $('#sn').onclick = () => { st.page++; load(); };
  });
  let t;
  $('#sq').oninput = (e) => { clearTimeout(t); t = setTimeout(() => { st.q = e.target.value; st.page = 1; load(); }, 250); };
  $('#ss').onchange = (e) => { st.status = e.target.value; st.page = 1; load(); };
  load();
});
route(/^\/software\/(\d+)$/, async (v, q, id) => {
  const s = await GET(`/api/software/${id}`);
  v.innerHTML = head(`${esc(s.name)} ${pill(s.status, s.status === 'neutral' ? 'Unclassified' : null)}`, can('tech') ? '<button class="btn primary" id="clsBtn">Classify</button>' : '', '<a href="#/software">Software</a>')
    + `<div class="grid g2" style="margin-bottom:16px"><div class="card"><dl class="kv"><dt>Publisher</dt><dd>${esc(s.publisher || '—')}</dd><dt>Category</dt><dd>${esc(s.category || '—')}</dd>
      <dt>Installations</dt><dd>${s.installs.length}</dd><dt>First seen</dt><dd>${fmtDT(s.first_seen)}</dd><dt>Notes</dt><dd>${esc(s.notes || '')}</dd></dl></div>
      <div class="card"><h2>Versions</h2>${bars(s.versions, { label: (r) => r.version || '(no version)', value: (r) => r.n })}</div></div>
      <h2>Installed on</h2>${table([{ key: 'name', render: (a) => `<a href="#/assets/${a.id}">${esc(a.name)}</a>` }, { key: 'asset_tag', label: 'Tag' }, { key: 'version' },
        { key: 'last_user', label: 'User' }, { key: 'install_date', label: 'Installed' }, { key: 'status', render: (a) => pill(a.status) }], s.installs, { empty: 'Not installed anywhere' })}`;
  if ($('#clsBtn')) $('#clsBtn').onclick = () => formModal({
    title: 'Classify software', values: s,
    fields: [{ name: 'status', label: 'Status', type: 'select', blank: false, options: [{ value: 'neutral', label: 'Unclassified' }, { value: 'authorized', label: 'Authorized' }, { value: 'prohibited', label: 'Prohibited (raise alerts)' }] },
      { name: 'category', label: 'Category', placeholder: 'e.g. Browser, Office, Security' }, { name: 'notes', label: 'Notes', type: 'textarea', full: true }],
    onSubmit: async (val) => { await api('PUT', `/api/software/${id}`, val); toast('Saved'); reload(); },
  });
});

// ------------------------------------------------------------------ licenses
const LIC_FIELDS = [
  { name: 'name', label: 'License name', required: true, full: true },
  { name: 'software_match', label: 'Matches installed software', full: true, placeholder: 'e.g. Microsoft Office; Visio', help: 'Names to match (contains). Separate several with ";". Use % as wildcard.' },
  { name: 'license_type', label: 'Metric', type: 'select', blank: false, options: [{ value: 'per_device', label: 'Per device' }, { value: 'per_user', label: 'Per user' }, { value: 'site', label: 'Site / unlimited' }] },
  { name: 'seats', label: 'Seats owned', type: 'number' }, { name: 'vendor', label: 'Vendor' }, { name: 'cost', label: 'Cost', type: 'number' },
  { name: 'purchase_date', label: 'Purchase date', type: 'date' }, { name: 'expiry_date', label: 'Expiry / renewal date', type: 'date' },
  { name: 'license_key', label: 'License key', full: true }, { name: 'notes', label: 'Notes', type: 'textarea', full: true },
];
route(/^\/licenses$/, async (v) => {
  const rows = await GET('/api/licenses');
  v.innerHTML = head('Software licenses', can('tech') ? `<button class="btn primary" id="newLic">${icon('plus', 'sm')} Add license</button>` : '') + table([
    { key: 'name', render: (l) => `<a href="#/licenses/${l.id}">${esc(l.name)}</a><div class="muted small">${esc(l.software_match || '')}</div>` },
    { key: 'vendor' }, { key: 'license_type', label: 'Metric', render: (l) => titleCase(l.license_type) },
    { key: 'usage', label: 'Usage', render: (l) => (l.seats ? `${l.used} / ${l.seats}${usageBar(l.used, l.seats, true)}` : `${l.used} / ∞`) },
    { key: 'expiry_date', label: 'Expires' }, { key: 'compliance', render: (l) => pill(l.compliance) }], rows,
  { empty: 'No licenses yet. Add one and point it at installed software to track compliance automatically.' });
  if ($('#newLic')) $('#newLic').onclick = () => formModal({ title: 'Add license', fields: LIC_FIELDS, values: { license_type: 'per_device' },
    onSubmit: async (val) => { const r = await api('POST', '/api/licenses', val); location.hash = `#/licenses/${r.id}`; } });
});
route(/^\/licenses\/(\d+)$/, async (v, q, id) => {
  const l = await GET(`/api/licenses/${id}`);
  v.innerHTML = head(`${esc(l.name)} ${pill(l.compliance)}`, can('tech') ? '<button class="btn primary" id="ed">Edit</button><button class="btn danger" id="del">Delete</button>' : '', '<a href="#/licenses">Licenses</a>')
    + `<div class="kpis"><div class="kpi"><div class="v">${l.used}</div><div class="l">In use</div></div><div class="kpi"><div class="v">${l.seats ?? '∞'}</div><div class="l">Owned</div></div>
      <div class="kpi ${l.seats !== null && l.used > l.seats ? 'crit' : 'ok'}"><div class="v">${l.seats === null ? '∞' : l.seats - l.used}</div><div class="l">Available</div></div>
      <div class="kpi"><div class="v" style="font-size:18px;padding:5px 0">${money(l.cost)}</div><div class="l">Cost</div></div></div>
    <div class="card" style="margin-bottom:16px"><dl class="kv"><dt>Metric</dt><dd>${titleCase(l.license_type)}</dd><dt>Matches</dt><dd class="mono">${esc(l.software_match || '—')}</dd>
      <dt>Vendor</dt><dd>${esc(l.vendor || '')}</dd><dt>Purchased</dt><dd>${esc(l.purchase_date || '')}</dd><dt>Expires</dt><dd>${esc(l.expiry_date || '')}</dd>
      <dt>Key</dt><dd class="mono">${esc(l.license_key || (can('tech') ? '' : 'hidden'))}</dd><dt>Notes</dt><dd>${esc(l.notes || '')}</dd></dl></div>
    <h2>Detected installations</h2>${table([{ key: 'name', render: (a) => `<a href="#/assets/${a.id}">${esc(a.name)}</a>` }, { key: 'asset_tag', label: 'Tag' },
      { key: 'software' }, { key: 'version' }, { key: 'person', label: 'Assigned to' }, { key: 'last_user', label: 'Last user' }], l.installs, { empty: 'No matching installations found' })}`;
  if ($('#ed')) {
    $('#ed').onclick = () => formModal({ title: 'Edit license', fields: LIC_FIELDS, values: l, onSubmit: async (val) => { await api('PUT', `/api/licenses/${id}`, val); reload(); } });
    $('#del').onclick = guard(async () => { if (await confirmBox('Delete this license?')) { await api('DELETE', `/api/licenses/${id}`); location.hash = '#/licenses'; } });
  }
});

// ------------------------------------------------------------------ contracts
const CON_FIELDS = [
  { name: 'name', label: 'Contract name', required: true, full: true },
  { name: 'contract_type', label: 'Type', type: 'select', blank: false, options: opts(['support', 'warranty', 'maintenance', 'lease', 'subscription', 'insurance', 'other']) },
  { name: 'vendor', label: 'Vendor' }, { name: 'number', label: 'Contract #' }, { name: 'cost', label: 'Cost', type: 'number' },
  { name: 'start_date', label: 'Start', type: 'date' }, { name: 'end_date', label: 'End', type: 'date' },
  { name: 'renewal', label: 'Renewal terms', full: true }, { name: 'notes', label: 'Notes', type: 'textarea', full: true },
];
route(/^\/contracts$/, async (v) => {
  const rows = await GET('/api/contracts');
  const t = new Date().toISOString().slice(0, 10);
  v.innerHTML = head('Contracts', can('tech') ? `<button class="btn primary" id="newC">${icon('plus', 'sm')} Add contract</button>` : '') + table([
    { key: 'name', render: (c) => `<a href="#/contracts/${c.id}">${esc(c.name)}</a>` }, { key: 'contract_type', label: 'Type', render: (c) => titleCase(c.contract_type) },
    { key: 'vendor' }, { key: 'number', label: '#' }, { key: 'start_date', label: 'Start' },
    { key: 'end_date', label: 'End', render: (c) => `${esc(c.end_date || '')} ${c.end_date && c.end_date < t ? pill('expired', 'Expired') : ''}` },
    { key: 'cost', num: true, render: (c) => money(c.cost) }, { key: 'asset_count', label: 'Assets', num: true }], rows, { empty: 'No contracts yet' });
  if ($('#newC')) $('#newC').onclick = () => formModal({ title: 'Add contract', fields: CON_FIELDS, values: { contract_type: 'support' },
    onSubmit: async (val) => { const r = await api('POST', '/api/contracts', val); location.hash = `#/contracts/${r.id}`; } });
});
route(/^\/contracts\/(\d+)$/, async (v, q, id) => {
  const c = await GET(`/api/contracts/${id}`);
  v.innerHTML = head(esc(c.name), can('tech') ? `<button class="btn" id="link">${icon('plus', 'sm')} Link assets</button><button class="btn primary" id="ed">Edit</button><button class="btn danger" id="del">Delete</button>` : '', '<a href="#/contracts">Contracts</a>')
    + `<div class="card" style="margin-bottom:16px"><dl class="kv"><dt>Type</dt><dd>${titleCase(c.contract_type)}</dd><dt>Vendor</dt><dd>${esc(c.vendor || '')}</dd><dt>Number</dt><dd>${esc(c.number || '')}</dd>
      <dt>Period</dt><dd>${esc(c.start_date || '?')} → ${esc(c.end_date || '?')}</dd><dt>Cost</dt><dd>${money(c.cost)}</dd><dt>Renewal</dt><dd>${esc(c.renewal || '')}</dd><dt>Notes</dt><dd>${esc(c.notes || '')}</dd></dl></div>
    <h2>Covered assets</h2>${table([{ key: 'name', render: (a) => `<a href="#/assets/${a.id}">${esc(a.name)}</a>` }, { key: 'asset_tag', label: 'Tag' }, { key: 'type', render: (a) => titleCase(a.type) },
      { key: 'status', render: (a) => pill(a.status) }, ...(can('tech') ? [{ key: 'x', label: '', render: (a) => `<button class="btn sm danger" data-un="${a.id}">Unlink</button>` }] : [])], c.assets, { empty: 'No assets linked' })}`;
  $$('[data-un]').forEach((b) => b.onclick = guard(async () => { await api('DELETE', `/api/contracts/${id}/assets/${b.dataset.un}`); reload(); }));
  if ($('#ed')) {
    $('#ed').onclick = () => formModal({ title: 'Edit contract', fields: CON_FIELDS, values: c, onSubmit: async (val) => { await api('PUT', `/api/contracts/${id}`, val); reload(); } });
    $('#del').onclick = guard(async () => { if (await confirmBox('Delete this contract?')) { await api('DELETE', `/api/contracts/${id}`); location.hash = '#/contracts'; } });
    $('#link').onclick = () => assetPicker({ title: 'Link assets to contract', onPick: async (ids) => { await api('POST', `/api/contracts/${id}/assets`, { asset_ids: ids }); reload(); } });
  }
});

// ------------------------------------------------------------------ people / locations / departments
function orgPages(base, title, fields, cols) {
  route(new RegExp(`^/${base}$`), async (v) => {
    const rows = await GET(`/api/${base}`);
    v.innerHTML = head(title, can('tech') ? '<button class="btn primary" id="newO">+ Add</button>' : '') + table([
      { key: 'name', render: (r) => `<a href="#/${base}/${r.id}">${esc(r.name)}</a>` }, ...cols, { key: 'asset_count', label: 'Assets', num: true }], rows, { empty: `No ${title.toLowerCase()} yet` });
    if ($('#newO')) $('#newO').onclick = () => formModal({ title: `Add ${title.toLowerCase().replace(/s$/, '').replace(/ie$/, 'y').replace('peopl', 'person')}`, fields: fields(),
      onSubmit: async (val) => { await api('POST', `/api/${base}`, val); await refreshMeta(); reload(); } });
  });
  route(new RegExp(`^/${base}/(\\d+)$`), async (v, q, id) => {
    const r = await GET(`/api/${base}/${id}`);
    v.innerHTML = head(esc(r.name), `${base === 'people' && hasPerm('admin.all') ? '<button class="btn" id="loginBtn">Enable self-service login</button>' : ''}${base === 'locations' ? `<a class="btn" href="#/map?focus=${r.id}">Show on map</a>` : ''}${can('tech') ? '<button class="btn primary" id="ed">Edit</button><button class="btn danger" id="del">Delete</button>' : ''}`, `<a href="#/${base}">${title}</a>`)
      + `<div class="card" style="margin-bottom:16px"><dl class="kv">${fields().filter((f) => f.name !== 'name').map((f) => {
        let val = r[f.name];
        if (f.type === 'select' && val) val = f.options.find((o) => String(o.value) === String(val))?.label ?? val;
        return `<dt>${esc(f.label)}</dt><dd>${esc(val ?? '')}</dd>`;
      }).join('')}</dl></div><h2>Assets</h2>${table([{ key: 'name', render: (a) => `<a href="#/assets/${a.id}">${esc(a.name)}</a>` }, { key: 'asset_tag', label: 'Tag' },
        { key: 'type', render: (a) => titleCase(a.type) }, { key: 'status', render: (a) => pill(a.status) }], r.assets || [], { empty: 'No assets' })}`;
    if ($('#loginBtn')) $('#loginBtn').onclick = () => formModal({ title: `Self-service login for ${r.name}`, submitLabel: 'Create login', values: { username: r.email || '' },
      fields: [{ name: 'username', label: 'Username', required: true, full: true }, { name: 'password', label: 'Initial password', type: 'password', required: true, full: true, help: 'They must change it at first sign-in. They will only see their own assets.' }],
      onSubmit: async (val) => { await api('POST', `/api/people/${id}/login`, val); toast('Login created'); } });
    if ($('#ed')) {
      $('#ed').onclick = () => formModal({ title: 'Edit', fields: fields(), values: r, onSubmit: async (val) => { await api('PUT', `/api/${base}/${id}`, val); await refreshMeta(); reload(); } });
      $('#del').onclick = guard(async () => { if (await confirmBox(`Delete ${r.name}? Assets keep existing but lose this link.`)) { await api('DELETE', `/api/${base}/${id}`); await refreshMeta(); location.hash = `#/${base}`; } });
    }
  });
}
orgPages('people', 'People', () => [{ name: 'name', label: 'Full name', required: true }, { name: 'email', label: 'Email', type: 'email' },
  { name: 'username', label: 'Windows username', help: 'e.g. DOMAIN\\jsmith' }, { name: 'employee_number', label: 'Employee number' },
  { name: 'company_id', label: 'Company', type: 'select', options: opts(S.meta.companies) }, { name: 'title', label: 'Job title' }, { name: 'phone', label: 'Phone' },
  { name: 'department_id', label: 'Department', type: 'select', options: opts(S.meta.departments) }, { name: 'location_id', label: 'Location', type: 'select', options: opts(S.meta.locations) },
  { name: 'notes', label: 'Notes', type: 'textarea', full: true }],
[{ key: 'email' }, { key: 'title' }, { key: 'department' }, { key: 'location' }]);
orgPages('locations', 'Locations', () => [{ name: 'name', label: 'Name', required: true }, { name: 'address', label: 'Address' }, { name: 'notes', label: 'Notes', type: 'textarea', full: true }], [{ key: 'address' }]);
orgPages('departments', 'Departments', () => [{ name: 'name', label: 'Name', required: true }, { name: 'notes', label: 'Notes', type: 'textarea', full: true }], [{ key: 'notes' }]);

// ------------------------------------------------------------------ alerts
route(/^\/alerts$/, async (v, q) => {
  const state = q.state || 'open';
  const rows = await GET(`/api/alerts?state=${state === 'resolved' ? 'resolved' : 'open'}`);
  v.innerHTML = head('Alerts', `<a class="btn ${state === 'open' ? 'primary' : ''}" href="#/alerts">Open</a><a class="btn ${state === 'resolved' ? 'primary' : ''}" href="#/alerts?state=resolved">Resolved</a>
    ${can('tech') ? '<button class="btn" id="re">Re-evaluate now</button>' : ''}`)
    + '<p class="muted small">Alerts are raised and resolved automatically: low disk space, agents not reporting, prohibited software, license over-use or expiry, warranty and contract expiry. Thresholds are in Settings.</p>'
    + table([{ key: 'severity', render: (a) => pill(a.severity) }, { key: 'kind', label: 'Type', render: (a) => titleCase(a.kind) },
      { key: 'message', render: (a) => `${a.asset_id ? `<a href="#/assets/${a.asset_id}">${esc(a.message)}</a>` : esc(a.message)}${a.acknowledged ? ' <span class="pill">Acknowledged</span>' : ''}` },
      { key: 'created_at', label: 'Raised', render: (a) => ago(a.created_at) }, ...(state === 'resolved' ? [{ key: 'resolved_at', label: 'Resolved', render: (a) => fmtDT(a.resolved_at) }] : []),
      ...(can('tech') && state !== 'resolved' ? [{ key: 'x', label: '', render: (a) => (a.acknowledged ? '' : `<button class="btn sm" data-ack="${a.id}">Acknowledge</button>`) }] : [])],
    rows, { empty: state === 'resolved' ? 'No resolved alerts' : 'All clear — no open alerts' });
  $$('[data-ack]').forEach((b) => b.onclick = guard(async () => { await api('POST', `/api/alerts/${b.dataset.ack}/ack`); reload(); }));
  if ($('#re')) $('#re').onclick = guard(async () => { await api('POST', '/api/alerts/refresh'); refreshAlertBadge(); reload(); });
});

// ------------------------------------------------------------------ discovery
route(/^\/discovery$/, async (v) => {
  const d = await GET('/api/discovery');
  const job = d.job;
  v.innerHTML = head('Network discovery') + `
    <div class="card" style="margin-bottom:16px"><h2>Scan a network</h2>
      <p class="muted small" style="margin-top:0">Finds devices without the agent (printers, switches, servers, IoT) using ping and a TCP port fingerprint, then reverse-DNS and the ARP table. Scans run from the portal server.</p>
      ${can('tech') ? `<div class="filters"><input id="tg" style="width:320px" placeholder="192.168.1.0/24, 10.0.0.10-50" value="${esc(job?.targets || '')}"><button class="btn primary" id="scan" ${job?.running ? 'disabled' : ''}>Start scan</button></div>` : ''}
      ${job ? `<div class="small">${job.running ? `Scanning… ${job.done}/${job.total} addresses, ${job.found} hosts found` : `Last scan of <b>${esc(job.targets)}</b> finished ${ago(job.finished_at)} — ${job.found} hosts responded${job.error ? ` · error: ${esc(job.error)}` : ''}`}
        ${job.running ? usageBar(job.done, job.total) : ''}</div>` : ''}</div>
    ${table([{ key: 'ip', label: 'IP', render: (r) => `<span class="mono">${esc(r.ip)}</span>` }, { key: 'hostname' }, { key: 'mac', render: (r) => `<span class="mono small">${esc(r.mac || '')}</span>` },
      { key: 'guess_type', label: 'Probable type', render: (r) => titleCase(r.guess_type) }, { key: 'open_ports', label: 'Open ports' }, { key: 'last_seen', label: 'Seen', render: (r) => ago(r.last_seen) },
      { key: 'asset', label: 'Managed', render: (r) => (r.asset_id ? `<a href="#/assets/${r.asset_id}">${esc(r.asset_name)}</a>` : can('tech') ? `<button class="btn sm primary" data-imp="${r.id}">Add as asset</button> <button class="btn sm" data-ign="${r.id}">Dismiss</button>` : pill('warning', 'Unmanaged')) }],
    d.results, { empty: 'No scan results yet' })}`;
  if ($('#scan')) $('#scan').onclick = guard(async () => { await api('POST', '/api/discovery/scan', { targets: $('#tg').value }); reload(); });
  $$('[data-imp]').forEach((b) => b.onclick = guard(async () => { const r = await api('POST', `/api/discovery/${b.dataset.imp}/import`); toast('Asset created'); location.hash = `#/assets/${r.id}`; }));
  $$('[data-ign]').forEach((b) => b.onclick = guard(async () => { await api('DELETE', `/api/discovery/${b.dataset.ign}`); reload(); }));
  if (job?.running) setTimeout(() => { if (location.hash.startsWith('#/discovery')) reload(); }, 2000);
});

// ------------------------------------------------------------------ agents & deploy
const copyBtn = (text) => `<div class="copy-row"><button class="btn sm ghost" data-copy="${esc(text)}">${icon('copy', 'sm')} Copy</button></div>`;
route(/^\/agents$/, async (v) => {
  const [info, agents] = await Promise.all([GET('/api/agent-info'), GET('/api/agents')]);
  const srv = info.server_url;
  const key = info.enrollment_key;
  const online = agents.filter((a) => a.online).length;
  const local = /\/\/(localhost|127\.|\[::1\])/i.test(srv);
  const ps = `powershell -ExecutionPolicy Bypass -Command "iwr -UseBasicParsing '${srv}/download/install.ps1?key=${key}' | iex"`;
  const silent = `AssetAgentSetup.exe /quiet --server ${srv} --key ${key}`;
  v.innerHTML = head('Agents & deployment', '', '', 'Install the Windows agent to inventory computers automatically.') + `
    ${local ? callout('crit', `Agents will be told to contact <b>${esc(srv)}</b>, which only works on the server itself. Open the portal by its network name or IP
      (e.g. <span class="mono">http://192.168.x.x:8080</span>) or set the <a href="#/settings">Public portal URL</a> before downloading the installer.`) : ''}
    ${!info.exe_available ? callout('warn', 'The agent installer has not been built yet. On the portal server run <code>agent\\build.ps1</code>.') : ''}
    <div class="kpis">
      <div class="kpi ok"><span class="chip">${icon('monitor')}</span><div><div class="v">${online}</div><div class="l">Online now</div></div></div>
      <div class="kpi"><span class="chip">${icon('monitor')}</span><div><div class="v">${agents.length - online}</div><div class="l">Offline</div></div></div>
      <div class="kpi"><span class="chip">${icon('download')}</span><div><div class="v" style="font-size:20px">${info.package ? `v${esc(info.package.version)}` : '—'}</div><div class="l">Current agent version</div></div></div>
      <div class="kpi ok"><span class="chip">${icon('lock')}</span><div><div class="v" style="font-size:15px;padding:4px 0">AES-256-GCM</div><div class="l">End-to-end encrypted channel</div></div></div>
    </div>
    <div class="grid g2" style="margin-bottom:18px">
      <div class="card"><div class="card-head"><h2>Install on a computer</h2></div>
        ${key ? `<ol class="steps">
          <li><div><b>Download the installer</b><div class="muted small">Pre-configured for this portal — the user does not have to type anything.</div>
            <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap">${info.exe_available ? `<a class="btn primary" href="/download/setup?key=${esc(key)}">${icon('download', 'sm')} Download installer</a>
            <a class="btn" href="/download/AssetAgentSetup.exe">Generic installer</a>` : '<span class="muted">Not available yet</span>'}</div></div></li>
          <li><div><b>Run it on the computer</b><div class="muted small">Approve the administrator prompt, click <i>Next</i> and <i>Install</i>. Keep the downloaded file name unchanged.</div></div></li>
          <li><div><b>Done</b><div class="muted small">The computer appears in Assets within seconds and stays up to date automatically.</div></div></li>
        </ol>` : '<p class="muted">Ask an administrator or technician for access to the installer.</p>'}
      </div>
      <div class="card"><div class="card-head"><h2>Portal identity</h2></div>
        <p class="small muted" style="margin-top:0">Agents verify this key before sending any data. Installers downloaded here have it pinned; with the generic installer, users can compare it on the "Ready to install" page.</p>
        <div class="fingerprint">${esc(info.fingerprint)}</div>
        ${key ? `<h3>Enrollment key</h3><pre class="cmd">${esc(key)}</pre>${copyBtn(key)}
          <p class="small muted">Allows registering new computers. Rotating it does not affect computers that are already enrolled.</p>
          ${can('admin') ? '<button class="btn" id="rot">' + icon('refresh', 'sm') + ' Rotate key</button>' : ''}` : ''}
      </div>
    </div>
    ${key ? `<div class="card" style="margin-bottom:18px"><div class="card-head"><h2>Mass deployment</h2></div>
      <h3>Group Policy, Intune (Win32 app), SCCM, PDQ — silent</h3><pre class="cmd">${esc(silent)}</pre>${copyBtn(silent)}
      <div class="grid g2"><div><h3>PowerShell one-liner (elevated)</h3><pre class="cmd">${esc(ps)}</pre>${copyBtn(ps)}</div>
      <div><h3>Silent uninstall</h3><pre class="cmd">"C:\\Program Files\\AssetAgent\\AssetAgent.exe" uninstall /quiet</pre>
        <p class="small muted">Exit code 0 = success. Setup log: <span class="mono">C:\\ProgramData\\AssetAgent\\logs\\setup.log</span>. Upgrades roll out automatically when a newer installer is published.</p></div></div>
    </div>` : ''}
    <div class="card-head"><h2>Enrolled agents</h2></div>${table([{ key: 'name', label: 'Computer', render: (a) => `<span class="dot ${a.online ? 'on' : ''}"></span><a class="cell-main" href="#/assets/${a.asset_id}">${esc(a.name)}</a>` },
      { key: 'os_name', label: 'OS' }, { key: 'last_user', label: 'User' }, { key: 'version' }, { key: 'last_ip', label: 'IP', render: (a) => `<span class="mono">${esc(a.last_ip || '')}</span>` },
      { key: 'last_heartbeat', label: 'Heartbeat', render: (a) => ago(a.last_heartbeat) }, { key: 'last_checkin', label: 'Inventory', render: (a) => ago(a.last_checkin) },
      ...(can('tech') ? [{ key: 'x', label: '', render: (a) => `<button class="btn sm" data-scan="${a.asset_id}">Rescan</button> <button class="btn sm danger" data-rm="${a.id}">Revoke</button>` }] : [])],
    agents, { empty: 'No agents enrolled yet — download the installer above.' })}`;
  $$('[data-scan]').forEach((b) => b.onclick = guard(async () => { await api('POST', `/api/assets/${b.dataset.scan}/scan`); toast('Rescan requested — results within a minute'); }));
  $$('[data-rm]').forEach((b) => b.onclick = guard(async () => {
    if (await confirmBox('Revoke this agent? The asset is kept. If the agent is still installed it re-enrolls automatically while the enrollment key is valid.')) { await api('DELETE', `/api/agents/${b.dataset.rm}`); reload(); }
  }));
  if ($('#rot')) $('#rot').onclick = guard(async () => { if (await confirmBox('Rotate the enrollment key? Installers and commands copied earlier will stop working for new computers.')) { await api('POST', '/api/settings/enrollment-key'); reload(); } });
});

// ------------------------------------------------------------------ reports
route(/^\/reports$/, async (v) => {
  const list = await GET('/api/reports');
  const groups = {};
  list.forEach((r) => (groups[r.group] ||= []).push(r));
  v.innerHTML = head('Reports') + `<div class="grid g3">${Object.entries(groups).map(([g, rs]) => `<div class="card"><h2>${esc(g)}</h2>
    ${rs.map((r) => `<div style="padding:4px 0"><a href="#/reports/${r.id}">${esc(r.title)}</a></div>`).join('')}</div>`).join('')}</div>`;
});
route(/^\/reports\/(\w+)$/, async (v, q, id) => {
  const rp = await GET(`/api/reports/${id}?${qs(q)}`);
  const linkCol = (c) => ({ ...c, render: (r) => (['name', 'asset'].includes(c.key) && r.id ? `<a href="#/assets/${r.id}">${esc(r[c.key])}</a>` : c.key === 'compliance' || c.key === 'status' ? pill(r[c.key]) : esc(c.key === 'k' ? titleCase(r.k) : r[c.key])) });
  const p = rp.param;
  v.innerHTML = head(esc(rp.title), `${p ? `<label class="small muted">${esc(p.name)} <input type="number" id="rpP" style="width:80px" value="${esc(q[p.name] || p.def)}"></label>` : ''}
    <a class="btn" href="/api/reports/${id}?${qs({ ...q, format: 'csv' })}">Export CSV</a><button class="btn" data-print>${icon('print', 'sm')} Print</button>`, '<a href="#/reports">Reports</a>')
    + (rp.chart && rp.rows.length ? `<div class="card" style="margin-bottom:16px">${bars(rp.rows, { label: (r) => titleCase(r.k) })}</div>` : '')
    + table(rp.columns.map(linkCol), rp.rows, { empty: 'Nothing to report' }) + `<p class="muted small">${rp.rows.length} rows</p>`;
  if ($('#rpP')) $('#rpP').onchange = (e) => { location.hash = `#/reports/${id}?${qs({ ...q, [p.name]: e.target.value })}`; };
});

// ------------------------------------------------------------------ monitoring
function fmtDur(sec) {
  sec = Math.round(sec || 0);
  if (sec < 60) return `${sec}s`;
  const h = Math.floor(sec / 3600), m = Math.round((sec % 3600) / 60);
  return h ? `${h}h ${m}m` : `${m}m`;
}
const shotUrl = (id) => `/api/screenshots/${id}/image`;
function lightbox(shots, start) {
  let i = start;
  const el = document.createElement('div');
  el.className = 'lightbox';
  const render = () => {
    const s = shots[i];
    el.innerHTML = `<div class="lb-top"><b>${esc(s.app || 'Screen')}</b><span class="muted">${esc(s.title || '')}</span>
      <span style="margin-left:auto" class="muted">${fmtDT(s.ts)} · ${i + 1}/${shots.length}</span>
      <a class="btn sm" href="${shotUrl(s.id)}" target="_blank" rel="noopener">Open</a><button data-close>${icon('x', 'sm')} Close</button></div>
      <img src="${shotUrl(s.id)}" alt="screenshot">
      ${shots.length > 1 ? `<button class="lb-nav prev" data-prev>‹</button><button class="lb-nav next" data-next>›</button>` : ''}`;
  };
  render();
  const close = () => { el.remove(); document.removeEventListener('keydown', key); };
  const key = (e) => { if (e.key === 'Escape') close(); if (e.key === 'ArrowRight') { i = (i + 1) % shots.length; render(); } if (e.key === 'ArrowLeft') { i = (i - 1 + shots.length) % shots.length; render(); } };
  el.addEventListener('click', (e) => {
    if (e.target.closest('[data-close]') || e.target === el) close();
    else if (e.target.closest('[data-next]')) { i = (i + 1) % shots.length; render(); }
    else if (e.target.closest('[data-prev]')) { i = (i - 1 + shots.length) % shots.length; render(); }
  });
  document.addEventListener('keydown', key);
  document.body.appendChild(el);
}
function gallery(shots, { onDelete } = {}) {
  if (!shots.length) return '<div class="empty">' + icon('camera') + '<div>No screenshots in this period</div></div>';
  const html = `<div class="gallery">${shots.map((s, idx) => `<div class="shot" data-idx="${idx}">
    <img loading="lazy" src="${shotUrl(s.id)}" alt="">${onDelete ? `<button class="del" data-del="${s.id}" title="Delete">${icon('trash', 'sm')}</button>` : ''}
    <div class="meta"><b>${esc(s.app || '—')}</b><span>${new Date(s.ts).toLocaleTimeString()} · ${esc(s.title || '')}</span></div></div>`).join('')}</div>`;
  return html;
}
function wireGallery(root, shots, onDelete) {
  $$('.shot', root).forEach((el) => el.onclick = (e) => {
    if (e.target.closest('[data-del]')) return;
    lightbox(shots, Number(el.dataset.idx));
  });
  if (onDelete) $$('[data-del]', root).forEach((b) => b.onclick = guard(async (e) => { e.stopPropagation(); if (await confirmBox('Delete this screenshot?')) { await api('DELETE', `/api/screenshots/${b.dataset.del}`); onDelete(); } }));
}

route(/^\/monitoring$/, async (v) => {
  const d = await GET('/api/monitoring');
  const p = d.policy;
  const on = p.enabled;
  v.innerHTML = head(`Activity &amp; screens ${on ? pill('ok', 'Monitoring on') : pill('warn', 'Monitoring off')}`, '', '',
    'Application usage, screenshots and location from managed computers.') + `
    ${callout(on ? 'ok' : 'info', on
      ? `Monitoring is active. Users see a tray icon and notice on their computer. Screenshots: <b>${p.screenshots ? `every ${p.screenshot_interval_min} min` : 'off'}</b> · Location: <b>${p.location ? 'on' : 'off'}</b> · Data kept <b>${esc(d.settings.monitoring_retention_days)} days</b>.`
      : 'Monitoring is off. It records the active application, window titles, periodic screenshots and coarse location — on organization-managed devices, with the user notified. It never records keystrokes or passwords.')}
    <div id="monCfg"></div>
    <div class="kpis">
      <div class="kpi"><span class="chip">${icon('monitor')}</span><div><div class="v">${d.active_now.length}</div><div class="l">Active in last 6 min</div></div></div>
      <div class="kpi"><span class="chip">${icon('camera')}</span><div><div class="v">${d.shots_today}</div><div class="l">Screenshots today</div></div></div>
      <div class="kpi"><span class="chip">${icon('download')}</span><div><div class="v">${d.agents}</div><div class="l">Agents deployed</div></div></div>
      <div class="kpi"><span class="chip">${icon('clock')}</span><div><div class="v" style="font-size:18px">${fmtDur((d.by_category.reduce((s, c) => s + c.n, 0)))}</div><div class="l">Active time today</div></div></div>
    </div>
    <div class="grid g2" style="margin-bottom:18px">
      <div class="card"><div class="card-head"><h2>Active right now</h2></div>
        ${table([{ key: 'name', label: 'User / device', render: (a) => `<div class="live-app"><span class="appdot"></span><div><a class="cell-main" href="#/assets/${a.id}?tab=activity">${esc(a.cur_os_user || a.name)}</a><div class="cell-sub">${esc(a.name)}</div></div></div>` },
          { key: 'cur_app', label: 'Application', render: (a) => `<b>${esc(a.cur_app || '—')}</b><div class="cell-sub">${esc(a.cur_title || '')}</div>` },
          { key: 'loc_label', label: 'Location', render: (a) => esc(a.loc_label || '') }, { key: 'activity_at', label: 'Seen', render: (a) => ago(a.activity_at) }],
        d.active_now, { empty: 'Nobody is active right now' })}</div>
      <div class="card"><div class="card-head"><h2>Time by category (today)</h2></div>${donut(d.by_category.filter((c) => c.n), { label: (r) => r.k, value: (r) => r.n, center: 'active', })}
        <div class="muted small" style="margin-top:8px">Values are active seconds.</div></div>
    </div>
    <div class="card" style="margin-bottom:18px"><div class="card-head"><h2>Top applications today</h2></div>
      ${d.top_apps.length ? bars(d.top_apps, { label: (a) => `${a.app} · ${a.category}`, value: (a) => a.secs }).replace(/>(\d[\d,]*)</g, (m, n) => `>${fmtDur(Number(n.replace(/,/g, '')))}<`) : '<div class="empty">No activity recorded today</div>'}</div>
    <div class="card"><div class="card-head"><h2>Recent screenshots</h2><a class="actions small" href="#/monitoring">Refresh</a></div><div id="recentShots">${gallery(d.recent_shots)}</div></div>`;
  wireGallery($('#recentShots'), d.recent_shots);

  // admin configuration
  if (can('admin')) {
    const s = d.settings;
    const sw = (key, label, sub, checked) => `<div class="toggle-row"><div class="tl">${label}<small>${sub}</small></div>
      <label class="switch"><input type="checkbox" data-k="${key}" ${checked ? 'checked' : ''}><span></span></label></div>`;
    $('#monCfg').innerHTML = `<div class="card" style="margin-bottom:18px"><div class="card-head"><h2>Monitoring configuration</h2><div class="actions muted small">Administrator only</div></div>
      <div class="ack"><input type="checkbox" id="ack" ${on ? 'checked' : ''}><label for="ack" class="small">I confirm these are organization-owned or managed devices, and that users are informed that their activity may be monitored, as required by applicable law and policy.</label></div>
      ${sw('monitoring_enabled', 'Enable monitoring', 'Master switch. When off, the agent collects nothing.', s.monitoring_enabled === '1')}
      ${sw('activity_enabled', 'Application &amp; window activity', 'Active app and window titles (no keystrokes).', s.activity_enabled === '1')}
      ${sw('screenshot_enabled', 'Periodic screenshots', 'Capture the screen at an interval.', s.screenshot_enabled === '1')}
      ${sw('location_enabled', 'Coarse location', 'Wi-Fi network / IP-based location.', s.location_enabled === '1')}
      <div class="form-grid" style="margin-top:14px">
        <div class="field"><label>Screenshot interval (minutes)</label><input type="number" min="1" data-k="screenshot_interval_min" value="${esc(s.screenshot_interval_min)}"></div>
        <div class="field"><label>Idle threshold (seconds)</label><input type="number" min="30" data-k="idle_threshold_sec" value="${esc(s.idle_threshold_sec)}"></div>
        <div class="field"><label>Keep data for (days)</label><input type="number" min="1" data-k="monitoring_retention_days" value="${esc(s.monitoring_retention_days)}"></div>
        <div class="field full"><label>Notice shown to users on their computer</label><textarea data-k="monitoring_notice">${esc(s.monitoring_notice)}</textarea></div>
      </div>
      <div style="margin-top:14px"><button class="btn primary" id="saveMon">${icon('check', 'sm')} Save monitoring settings</button></div></div>`;
    $('#saveMon').onclick = guard(async () => {
      const body = {};
      $$('#monCfg [data-k]').forEach((el) => { body[el.dataset.k] = el.type === 'checkbox' ? (el.checked ? '1' : '0') : el.value; });
      if (body.monitoring_enabled === '1' && !$('#ack').checked) throw new Error('Please confirm the acknowledgment before enabling monitoring.');
      await api('PUT', '/api/settings', body);
      toast('Monitoring settings saved'); reload();
    });
  }
});

async function renderActivityTab(body, id, q) {
  const d = await GET(`/api/assets/${id}/activity?${qs({ day: q.day || '' })}`);
  if (!d.policy.enabled) { body.innerHTML = callout('info', 'Activity monitoring is currently turned off for the organization. Enable it under <a href="#/monitoring">Activity &amp; screens</a>.'); return; }
  const daySel = d.days_available.length ? `<select id="daySel">${d.days_available.map((day) => `<option value="${day}" ${day === d.day ? 'selected' : ''}>${day}</option>`).join('')}</select>` : `<span class="muted small">No data yet</span>`;
  body.innerHTML = `<div class="filters"><label class="small muted">Day</label>${daySel}
      ${can('tech') ? `<span style="margin-left:auto"></span>${d.policy.screenshots ? `<button class="btn sm" id="shotNow">${icon('camera', 'sm')} Capture screenshot now</button>` : ''}<button class="btn sm danger" id="purge">${icon('trash', 'sm')} Purge activity</button>` : ''}</div>
    <div class="facts"><div><small>Active time</small><b>${fmtDur(d.summary.active)}</b></div><div><small>Foreground time</small><b>${fmtDur(d.summary.total)}</b></div>
      <div><small>App sessions</small><b>${fmtNum(d.summary.events)}</b></div><div><small>Screenshots</small><b>${d.screenshots.length}</b></div>
      ${d.asset.activity_at ? `<div><small>Current app</small><b>${esc(d.asset.cur_app || '—')}</b></div>` : ''}</div>
    <div class="grid g2" style="margin-bottom:16px">
      <div class="card"><div class="card-head"><h2>By application</h2></div>${d.by_app.length ? bars(d.by_app.slice(0, 12), { label: (a) => a.app, value: (a) => a.secs }).replace(/>(\d[\d,]*)</g, (m, n) => `>${fmtDur(Number(n.replace(/,/g, '')))}<`) : '<div class="empty">No activity</div>'}</div>
      <div class="card"><div class="card-head"><h2>By category</h2></div>${donut(d.by_category.filter((c) => c.n), { label: (r) => r.k, value: (r) => r.n, center: 'active' })}</div>
    </div>
    ${d.locations.length ? `<div class="card" style="margin-bottom:16px"><div class="card-head"><h2>Location history</h2></div>${table([{ key: 'ts', label: 'Time', render: (l) => fmtDT(l.ts) },
      { key: 'label', label: 'Where', render: (l) => `${icon(l.method === 'wifi' ? 'wifi' : 'mapPin', 'sm')} ${esc(l.label || l.ssid || '')}` }, { key: 'private_ip', label: 'IP', render: (l) => `<span class="mono">${esc(l.private_ip || '')}</span>` },
      { key: 'coords', label: 'Map', render: (l) => (l.lat != null ? `<a target="_blank" rel="noopener" href="https://www.openstreetmap.org/?mlat=${l.lat}&mlon=${l.lng}#map=16/${l.lat}/${l.lng}">View</a>` : '') }], d.locations)}</div>` : ''}
    <div class="card" style="margin-bottom:16px"><div class="card-head"><h2>Screenshots</h2><div class="actions muted small">${d.policy.screenshots ? '' : 'Screenshots are turned off'}</div></div><div id="actShots">${gallery(d.screenshots, { onDelete: true })}</div></div>
    <div class="card"><div class="card-head"><h2>Activity timeline</h2></div>${table([{ key: 'ts', label: 'Time', render: (e) => new Date(e.ts).toLocaleTimeString() },
      { key: 'app', label: 'Application', render: (e) => `<b>${esc(e.app || e.process || '—')}</b>` }, { key: 'title', label: 'Window', render: (e) => `<span class="small">${esc(e.title || '')}</span>` },
      { key: 'category' }, { key: 'active_seconds', label: 'Active', num: true, render: (e) => fmtDur(e.active_seconds) }], d.timeline, { empty: 'No activity recorded for this day' })}</div>`;
  if ($('#daySel')) $('#daySel').onchange = (e) => { location.hash = `#/assets/${id}?tab=activity&day=${e.target.value}`; };
  wireGallery($('#actShots'), d.screenshots, () => reload());
  if ($('#shotNow')) $('#shotNow').onclick = guard(async () => { await api('POST', `/api/assets/${id}/screenshot`); toast('Screenshot requested — it will appear within a few minutes'); });
  if ($('#purge')) $('#purge').onclick = guard(async () => { if (await confirmBox('Delete all recorded activity, screenshots and location for this computer? This cannot be undone.')) { await api('DELETE', `/api/assets/${id}/activity`); toast('Activity purged'); reload(); } });
}

// ------------------------------------------------------------------ preferences (per user, this browser)
function prefGet(key, def) {
  try { const v = localStorage.getItem(`ap:${S.me?.username}:${key}`); return v === null ? def : JSON.parse(v); } catch { return def; }
}
function prefSet(key, val) { try { localStorage.setItem(`ap:${S.me?.username}:${key}`, JSON.stringify(val)); } catch { /* storage unavailable */ } }

// ------------------------------------------------------------------ asset table column registry
const DEFAULT_ASSET_COLS = ['asset_tag', 'name', 'type', 'status', 'os', 'ip', 'person', 'location', 'last_seen'];
function assetColumns() {
  return [
    { key: 'asset_tag', label: 'Tag', sort: 'asset_tag', render: (a) => `<span class="mono">${esc(a.asset_tag)}</span>` },
    { key: 'name', label: 'Name', sort: 'name', render: (a) => `<div class="cell-asset"><span class="type-ic">${icon(TYPE_ICON[a.type] || 'box', 'sm')}</span><div><a class="cell-main" href="#/assets/${a.id}">${esc(a.name)}</a><div class="cell-sub">${esc([a.manufacturer, a.model].filter(Boolean).join(' '))}</div></div></div>` },
    { key: 'type', label: 'Type', sort: 'type', render: (a) => titleCase(a.type) },
    { key: 'status', label: 'Status', sort: 'status', render: (a) => pill(a.status) },
    { key: 'os', label: 'OS', sort: 'os', render: (a) => `<span class="small">${esc(a.os_name || '')}</span>` },
    { key: 'ip', label: 'IP', sort: 'ip', render: (a) => `<span class="mono">${esc(a.ip || '')}</span>` },
    { key: 'person', label: 'Assigned to', sort: 'person', render: (a) => (a.person_id ? `<a href="#/people/${a.person_id}">${esc(a.person)}</a>` : `<span class="muted small">${esc(a.last_user || '')}</span>`) },
    { key: 'location', label: 'Location', sort: 'location', render: (a) => esc(a.location || '') },
    { key: 'department', label: 'Department', render: (a) => esc(a.department || '') },
    { key: 'company', label: 'Company', render: (a) => (a.company_id ? `<a href="#/assets?company_id=${a.company_id}">${esc(a.company)}</a>` : '') },
    { key: 'category', label: 'Category', render: (a) => esc(a.category || '') },
    { key: 'model_number', label: 'Model no.', render: (a) => `<span class="small">${esc(a.model_number || '')}</span>` },
    { key: 'order_number', label: 'Order no.', render: (a) => `<span class="mono small">${esc(a.order_number || '')}</span>` },
    { key: 'serial', label: 'Serial', render: (a) => `<span class="mono small">${esc(a.serial || '')}</span>` },
    { key: 'model', label: 'Model', sort: 'model', render: (a) => esc(a.model || '') },
    { key: 'cpu', label: 'CPU', render: (a) => `<span class="small">${esc(a.cpu || '')}</span>` },
    { key: 'ram', label: 'RAM', num: true, render: (a) => gbFromMb(a.ram_mb) },
    { key: 'disk', label: 'Free disk', num: true, render: (a) => (a.disk_total_gb ? `${fmtNum(a.disk_free_gb, 0)} / ${fmtNum(a.disk_total_gb, 0)} GB` : '') },
    { key: 'warranty_end', label: 'Warranty', sort: 'warranty_end', render: (a) => (a.warranty_end ? `${esc(a.warranty_end)}${a.warranty_end < new Date().toISOString().slice(0, 10) ? ' ' + pill('crit', 'Expired') : ''}` : '') },
    { key: 'purchase_cost', label: 'Cost', num: true, render: (a) => money(a.purchase_cost) },
    { key: 'agent_version', label: 'Agent', render: (a) => (a.agent_id ? `<span class="dot ${a.online ? 'on' : ''}"></span>${esc(a.agent_version || '')}` : '<span class="muted small">—</span>') },
    { key: 'last_seen', label: 'Last seen', sort: 'last_seen', render: (a) => `<span class="small">${a.agent_id ? `<span class="dot ${a.online ? 'on' : ''}"></span>` : ''}${a.last_seen ? ago(a.last_seen) : `<span class="muted">${esc(titleCase(a.source))}</span>`}</span>` },
  ];
}

/** Open a dropdown on whichever side has room, so it never covers the sidebar or leaves the window. */
function placeMenu(m) {
  m.style.left = '0'; m.style.right = 'auto';
  const r = m.getBoundingClientRect();
  if (r.right > window.innerWidth - 8) { m.style.left = 'auto'; m.style.right = '0'; }
}

// ------------------------------------------------------------------ loading skeleton
const skeleton = () => `<div class="skel"><div class="sk sk-title"></div><div class="sk sk-sub"></div>
  <div class="kpis">${'<div class="sk sk-kpi"></div>'.repeat(4)}</div><div class="sk sk-block"></div><div class="sk sk-block short"></div></div>`;

// ------------------------------------------------------------------ command palette (Ctrl+K)
function paletteCommands() {
  const nav = NAV.flatMap(([g, items]) => items.filter((i) => navAllowed(i[0])).map(([id, label, ic]) => ({ label, hint: g, icon: ic, run: () => { location.hash = `#/${id}`; } })));
  const actions = [
    ...(can('tech') ? [{ label: 'Add asset', hint: 'Action', icon: 'plus', run: () => newAssetModal() },
      { label: 'Import assets from CSV', hint: 'Action', icon: 'upload', run: () => { location.hash = '#/import'; } },
      { label: 'Deploy agent', hint: 'Action', icon: 'download', run: () => { location.hash = '#/agents'; } },
      { label: 'Scan the network', hint: 'Action', icon: 'radar', run: () => { location.hash = '#/discovery'; } }] : []),
    { label: 'Toggle dark mode', hint: 'Action', icon: 'moon', run: () => $('#themeBtn')?.click() },
    { label: 'Keyboard shortcuts', hint: 'Help', icon: 'info', run: () => shortcutsHelp() },
    { label: 'My security & two-factor', hint: 'Account', icon: 'shieldCheck', run: () => { location.hash = '#/security'; } },
    { label: 'Sign out', hint: 'Account', icon: 'logout', run: () => $('#logout')?.click() },
  ];
  return [...actions, ...nav];
}
function openPalette() {
  if ($('.palette-back')) return;
  const back = document.createElement('div');
  back.className = 'palette-back';
  back.innerHTML = `<div class="palette" role="dialog" aria-label="Command palette">
    <div class="pal-input">${icon('search')}<input id="palQ" placeholder="Search pages, actions, assets, people, software…" autocomplete="off"><kbd>Esc</kbd></div>
    <div class="pal-list" id="palList"></div><div class="pal-foot"><span><kbd>↑</kbd><kbd>↓</kbd> navigate</span><span><kbd>Enter</kbd> open</span><span><kbd>Ctrl</kbd><kbd>K</kbd> toggle</span></div></div>`;
  document.body.appendChild(back);
  const input = $('#palQ', back), list = $('#palList', back);
  let items = [], sel = 0, t;
  const close = () => { back.remove(); document.removeEventListener('keydown', onKey, true); };
  const draw = () => {
    list.innerHTML = items.length ? items.map((it, i) => `<button class="pal-item ${i === sel ? 'sel' : ''}" data-i="${i}">${icon(it.icon || 'search', 'sm')}<span>${esc(it.label)}${it.sub ? `<small>${esc(it.sub)}</small>` : ''}</span><em>${esc(it.hint || '')}</em></button>`).join('')
      : '<div class="empty">No matches</div>';
    $$('.pal-item', list).forEach((b) => b.onclick = () => { const it = items[Number(b.dataset.i)]; close(); it.run(); });
    list.querySelector('.sel')?.scrollIntoView({ block: 'nearest' });
  };
  const update = () => {
    const q = input.value.trim().toLowerCase();
    const base = paletteCommands().filter((c) => !q || c.label.toLowerCase().includes(q) || (c.hint || '').toLowerCase().includes(q));
    items = base.slice(0, q ? 8 : 14); sel = 0; draw();
    clearTimeout(t);
    if (q.length >= 2) {
      t = setTimeout(async () => {
        try {
          const r = await GET(`/api/search?${qs({ q })}`);
          if (input.value.trim().toLowerCase() !== q) return;
          items = [...base.slice(0, 6),
            ...r.assets.map((a) => ({ label: a.name, sub: `${a.asset_tag} · ${a.serial || a.ip || ''}`, hint: 'Asset', icon: TYPE_ICON[a.type] || 'box', run: () => { location.hash = `#/assets/${a.id}`; } })),
            ...r.people.map((p) => ({ label: p.name, sub: p.email || '', hint: 'Person', icon: 'users', run: () => { location.hash = `#/people/${p.id}`; } })),
            ...r.software.map((s) => ({ label: s.name, sub: s.publisher || '', hint: 'Software', icon: 'layers', run: () => { location.hash = `#/software/${s.id}`; } }))];
          draw();
        } catch { /* ignore */ }
      }, 180);
    }
  };
  const onKey = (e) => {
    if (e.key === 'Escape') { e.preventDefault(); close(); }
    else if (e.key === 'ArrowDown') { e.preventDefault(); sel = Math.min(items.length - 1, sel + 1); draw(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); sel = Math.max(0, sel - 1); draw(); }
    else if (e.key === 'Enter' && items[sel]) { e.preventDefault(); const it = items[sel]; close(); it.run(); }
  };
  document.addEventListener('keydown', onKey, true);
  back.addEventListener('mousedown', (e) => { if (e.target === back) close(); });
  input.addEventListener('input', update);
  update(); input.focus();
}
function shortcutsHelp() {
  const rows = [['Ctrl + K', 'Command palette'], ['/', 'Focus search'], ['g then d', 'Dashboard'], ['g then a', 'Assets'], ['g then s', 'Software'],
    ['g then l', 'Licenses'], ['g then m', 'Activity & screens'], ['g then r', 'Reports'], ['n', 'New asset'], ['?', 'This help']];
  modal({ title: 'Keyboard shortcuts', body: `<table>${rows.map(([k, d]) => `<tr><td>${k.split(' ').map((x) => (/^(then|\+)$/.test(x) ? `<span class="muted small"> ${x} </span>` : `<kbd>${esc(x)}</kbd>`)).join('')}</td><td>${esc(d)}</td></tr>`).join('')}</table>` });
}
let gPending = 0;
document.addEventListener('keydown', (e) => {
  if (!S.me || S.me.role === 'user') return;
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); $('.palette-back') ? $('.palette-back').remove() : openPalette(); return; }
  const typing = /^(input|textarea|select)$/i.test(e.target.tagName) || e.target.isContentEditable;
  if (typing || e.ctrlKey || e.metaKey || e.altKey || $('.modal-back') || $('.palette-back')) return;
  if (e.key === '/') { e.preventDefault(); $('#gsearch')?.focus(); return; }
  if (e.key === '?') { shortcutsHelp(); return; }
  if (e.key === 'n' && can('tech')) { newAssetModal(); return; }
  if (e.key === 'g') { gPending = Date.now(); return; }
  if (Date.now() - gPending < 1200) {
    const dest = { d: 'dashboard', a: 'assets', s: 'software', l: 'licenses', m: 'monitoring', r: 'reports', c: 'checkouts', p: 'people' }[e.key];
    gPending = 0;
    if (dest) location.hash = `#/${dest}`;
  }
});
document.addEventListener('click', (e) => { if (!e.target.closest('.dd')) $$('.dd-menu').forEach((m) => { m.hidden = true; }); });

// ------------------------------------------------------------------ check-outs
function checkinModal(asset) {
  formModal({
    title: `Check in ${asset.name}`, submitLabel: 'Check in', values: { status: 'in_stock', condition: 'Good' },
    fields: [{ name: 'condition', label: 'Condition', type: 'select', blank: false, options: opts(['Good', 'Minor wear', 'Damaged', 'Missing accessories']) },
      { name: 'status', label: 'New status', type: 'select', blank: false, options: opts(S.meta.statuses) }, { name: 'notes', label: 'Notes', type: 'textarea', full: true }],
    onSubmit: async (v) => { await api('POST', `/api/assets/${asset.id}/checkin`, v); toast('Checked in'); reload(); },
  });
}
route(/^\/checkouts$/, async (v, q) => {
  const state = q.state || 'open';
  const rows = await GET(`/api/checkouts?state=${state}`);
  const tabsHtml = [['open', 'Checked out'], ['pending', 'Awaiting acceptance'], ['overdue', 'Overdue'], ['all', 'History']].map(([k, l]) => `<a class="btn ${state === k ? 'primary' : ''}" href="#/checkouts?state=${k}">${l}</a>`).join('');
  v.innerHTML = head('Check-outs', tabsHtml, '', 'Loaner equipment and temporary assignments, with due dates.') + table([
    { key: 'asset_name', label: 'Asset', render: (c) => `<div class="cell-asset"><span class="type-ic">${icon(TYPE_ICON[c.type] || 'box', 'sm')}</span><div><a class="cell-main" href="#/assets/${c.asset_id}">${esc(c.asset_name)}</a><div class="cell-sub mono">${esc(c.asset_tag)}</div></div></div>` },
    { key: 'person', label: 'Checked out to', render: (c) => (c.person_id ? `<a href="#/people/${c.person_id}">${esc(c.person)}</a><div class="cell-sub">${esc(c.email || '')}</div>` : c.location ? `${icon('pin', 'sm')} ${esc(c.location)}` : '—') + (c.accept_status ? `<div>${pill(c.accept_status === 'accepted' ? 'ok' : c.accept_status === 'declined' ? 'crit' : 'warn', c.accept_status === 'pending' ? 'Awaiting acceptance' : titleCase(c.accept_status))}</div>` : '') },
    { key: 'out_at', label: 'Out', render: (c) => `${fmtDate(c.out_at)}<div class="cell-sub">by ${esc(c.out_by || '')}</div>` },
    { key: 'due_at', label: 'Due', render: (c) => (c.due_at ? `${esc(c.due_at)} ${c.overdue ? pill('crit', 'Overdue') : ''}` : '<span class="muted">No due date</span>') },
    { key: 'in_at', label: 'Returned', render: (c) => (c.in_at ? `${fmtDate(c.in_at)}<div class="cell-sub">${esc(c.in_condition || '')}</div>` : pill('info', 'Out')) },
    ...(can('tech') && state !== 'all' ? [{ key: 'x', label: '', render: (c) => `<button class="btn sm" data-ci="${c.asset_id}" data-name="${esc(c.asset_name)}">Check in</button>` }] : []),
  ], rows, { empty: state === 'overdue' ? 'Nothing is overdue' : 'No check-outs' });
  $$('[data-ci]').forEach((b) => b.onclick = () => checkinModal({ id: Number(b.dataset.ci), name: b.dataset.name }));
});

// ------------------------------------------------------------------ security center
route(/^\/security-center$/, async (v) => {
  const [d, tokens] = await Promise.all([GET('/api/security'), GET('/api/tokens')]);
  const s = d.settings, p = d.posture;
  const https = location.protocol === 'https:';
  const checks = [
    [https, 'Portal served over HTTPS', 'Use a certificate (scripts\\new-cert.ps1) or a reverse proxy with TLS.'],
    [p.admins_without_2fa === 0, 'All administrators use two-factor', `${p.admins_without_2fa} of ${p.admins} administrators have no second factor.`],
    [s.require_2fa_admins === '1', 'Two-factor required for administrators', 'Turn on "Require two-factor for administrators" below.'],
    [d.audit.ok, 'Audit log integrity verified', `Chain broken at entry #${d.audit.broken_at} — the log was modified outside the portal.`],
    [!!s.portal_ip_allowlist, 'Portal restricted to trusted networks', 'Add your office/VPN ranges to the IP allowlist.'],
    [Number(s.session_idle_min) <= 30, 'Idle sessions time out within 30 minutes', `Currently ${s.session_idle_min} minutes.`],
    [p.failed_logins_24h < 20, 'No brute-force activity in the last 24 h', `${p.failed_logins_24h} failed sign-ins in the last 24 hours.`],
  ];
  const score = Math.round((checks.filter((c) => c[0]).length / checks.length) * 100);
  const scoreCls = score >= 85 ? 'ok' : score >= 60 ? 'warn' : 'crit';
  const sw = (key, label, sub) => `<div class="toggle-row"><div class="tl">${label}<small>${sub}</small></div><label class="switch"><input type="checkbox" data-sk="${key}" ${s[key] === '1' ? 'checked' : ''}><span></span></label></div>`;
  v.innerHTML = head('Security center', `<a class="btn" href="/api/audit/export">${icon('download', 'sm')} Export audit log</a>`, '', 'Posture, access controls, integrations and data protection.') + `
    <div class="grid g3" style="margin-bottom:18px">
      <div class="card score-card"><div class="score ${scoreCls}"><svg viewBox="0 0 120 120"><circle cx="60" cy="60" r="50" class="trk"/><circle cx="60" cy="60" r="50" class="val" stroke-dasharray="${(score / 100) * 314} 314"/></svg><b>${score}</b><small>Security score</small></div>
        <div class="small muted" style="text-align:center">${checks.filter((c) => c[0]).length} of ${checks.length} checks passed</div></div>
      <div class="card span2"><div class="card-head"><h2>Posture checks</h2></div><ul class="checks">${checks.map(([ok, t, fix]) => `<li class="${ok ? 'ok' : 'bad'}">${icon(ok ? 'check' : 'alert', 'sm')}<div><b>${t}</b>${ok ? '' : `<div class="small muted">${esc(fix)}</div>`}</div></li>`).join('')}</ul></div>
    </div>
    <div class="kpis">
      <div class="kpi"><span class="chip">${icon('users')}</span><div><div class="v">${p.users_with_2fa}<small> / ${p.users}</small></div><div class="l">Users with two-factor</div></div></div>
      <div class="kpi"><span class="chip">${icon('monitor')}</span><div><div class="v">${p.active_sessions}</div><div class="l">Active sessions</div></div></div>
      <div class="kpi ${p.failed_logins_24h ? 'warn' : 'ok'}"><span class="chip">${icon('lock')}</span><div><div class="v">${p.failed_logins_24h}</div><div class="l">Failed sign-ins (24 h)</div></div></div>
      <div class="kpi ${d.audit.ok ? 'ok' : 'crit'}"><span class="chip">${icon('list')}</span><div><div class="v">${fmtNum(d.audit.checked)}</div><div class="l">Audit entries ${d.audit.ok ? 'verified' : '— CHAIN BROKEN'}</div></div></div>
    </div>
    <div class="grid g2" style="margin-bottom:18px">
      <div class="card"><div class="card-head"><h2>Access policy</h2></div>
        ${sw('require_2fa_admins', 'Require two-factor for administrators', 'Admins must enrol an authenticator before making changes.')}
        <div class="form-grid" style="margin-top:12px">
          <div class="field"><label>Sign out after inactivity (min)</label><input type="number" min="5" data-sk="session_idle_min" value="${esc(s.session_idle_min)}"></div>
          <div class="field"><label>Max session length (hours)</label><input type="number" min="1" data-sk="session_max_hours" value="${esc(s.session_max_hours)}"></div>
          <div class="field"><label>Password expiry (days, 0 = never)</label><input type="number" min="0" data-sk="password_max_age_days" value="${esc(s.password_max_age_days)}"></div>
          <div class="field full"><label>Portal IP allowlist</label><textarea data-sk="portal_ip_allowlist" placeholder="e.g. 10.0.0.0/8, 192.168.1.0/24, 203.0.113.7">${esc(s.portal_ip_allowlist)}</textarea>
            <span class="muted small">Empty = allow all. Agents and installers are always allowed. Your address: <b class="mono">${esc(d.your_ip)}</b></span></div>
        </div>
        <button class="btn primary" id="saveAccess" style="margin-top:12px">${icon('check', 'sm')} Save access policy</button></div>
      <div class="card"><div class="card-head"><h2>Agent tamper protection</h2></div>
        ${sw('uninstall_protection', 'Require an uninstall code', 'Users cannot remove the agent without the code below. Admins can still uninstall with it.')}
        ${d.uninstall_code ? `<h3>Current uninstall code</h3><div style="display:flex;gap:8px;align-items:center"><span class="fingerprint" id="ucode" data-code="${esc(d.uninstall_code)}">•••• ••••</span>
          <button class="btn sm" id="showCode">${icon('eye', 'sm')} Reveal</button><button class="btn sm" id="rotCode">${icon('refresh', 'sm')} Rotate</button></div>
          <p class="small muted">Silent removal: <span class="mono">AssetAgent.exe uninstall /quiet /code=XXXXXXXX</span>. Devices pick up a new code within a minute.</p>` : '<p class="small muted">Turn the switch on to generate a code.</p>'}
        <h3>Data protection</h3>
        <ul class="checks"><li class="ok">${icon('check', 'sm')}<div>Agent traffic end-to-end encrypted (X25519 + AES-256-GCM)</div></li>
          <li class="ok">${icon('check', 'sm')}<div>Secrets, license keys and screenshots encrypted at rest</div></li>
          <li class="${p.master_key_env ? 'ok' : 'bad'}">${icon(p.master_key_env ? 'check' : 'info', 'sm')}<div>Master key ${p.master_key_env ? 'supplied from environment / secret store' : 'stored in data\\master.key — keep it out of normal file backups'}</div></li></ul></div>
    </div>
    <div class="grid g2" style="margin-bottom:18px">
      <div class="card"><div class="card-head"><h2>Alert notifications</h2></div>
        <div class="form-grid">
          <div class="field"><label>Destination</label><select data-sk="webhook_kind">${[['teams', 'Microsoft Teams (Workflows)'], ['slack', 'Slack incoming webhook'], ['generic', 'Generic JSON (signed)']].map(([k, l]) => `<option value="${k}" ${s.webhook_kind === k ? 'selected' : ''}>${l}</option>`).join('')}</select></div>
          <div class="field"><label>Minimum severity</label><select data-sk="webhook_min_severity">${['info', 'warning', 'critical'].map((k) => `<option value="${k}" ${s.webhook_min_severity === k ? 'selected' : ''}>${titleCase(k)}</option>`).join('')}</select></div>
          <div class="field full"><label>Webhook URL</label><input id="whUrl" placeholder="${esc(d.webhook_url_masked || 'https://…')}" autocomplete="off"><span class="muted small">${d.webhook_url_masked ? 'A URL is configured (stored encrypted). Leave empty to keep it.' : 'Not configured.'}</span></div>
          <div class="field full"><label>Signing secret (generic only)</label><input id="whSecret" type="password" placeholder="${d.webhook_secret_set ? '•••••••• (set)' : 'optional'}" autocomplete="new-password">
            <span class="muted small">Requests carry <span class="mono">X-AssetPortal-Signature: sha256=HMAC(timestamp.body)</span>.</span></div>
        </div>
        <div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary" id="saveHook">${icon('check', 'sm')} Save</button><button class="btn" id="testHook">Send test</button>
          ${d.webhook_url_masked ? '<button class="btn danger" id="clearHook">Remove</button>' : ''}</div>
        ${d.webhook_last ? `<p class="small muted">Last delivery ${ago(d.webhook_last.at)}: ${d.webhook_last.error ? `<span style="color:var(--crit)">${esc(d.webhook_last.error)}</span>` : `HTTP ${d.webhook_last.status}`} (${d.webhook_last.count} alert(s))</p>` : ''}</div>
      <div class="card"><div class="card-head"><h2>Encrypted backup</h2></div>
        <p class="small muted" style="margin-top:0">Downloads the full database plus the master key, encrypted with your passphrase (scrypt + AES-256-GCM). Without the passphrase the file is useless — store it separately.</p>
        <div class="field"><label>Backup passphrase (min 12 characters)</label><input type="password" id="bkPass" autocomplete="new-password"></div>
        <button class="btn primary" id="doBackup" style="margin-top:10px">${icon('download', 'sm')} Download backup</button>
        <p class="small muted">Restore (portal stopped): <span class="mono">node scripts\\restore.mjs backup.apbak</span></p>
        <h3>Audit log integrity</h3><p class="small muted" style="margin-top:0">Every entry is chained with SHA-256 to the previous one, so edits or deletions are detectable.</p>
        <button class="btn" id="verifyAudit">${icon('shieldCheck', 'sm')} Verify now</button> <span id="verifyOut" class="small"></span></div>
    </div>
    <div class="card"><div class="card-head"><h2>API tokens</h2><div class="actions"><button class="btn primary" id="newTok">${icon('plus', 'sm')} New token</button></div></div>
      <p class="small muted" style="margin-top:0">For Power BI, SIEM, ServiceNow and scripts: <span class="mono">Authorization: Bearer ap_…</span>. Tokens are never shown again after creation and can't administer the portal.</p>
      ${table([{ key: 'name', render: (t) => `<b>${esc(t.name)}</b><div class="cell-sub mono">ap_${esc(t.prefix)}_…</div>` }, { key: 'role', render: (t) => pill(t.role === 'tech' ? 'info' : '', titleCase(t.role === 'tech' ? 'technician' : t.role)) },
        { key: 'created_at', label: 'Created', render: (t) => `${fmtDate(t.created_at)}<div class="cell-sub">by ${esc(t.created_by || '')}</div>` },
        { key: 'expires_at', label: 'Expires', render: (t) => (t.expires_at ? (t.expires_at < new Date().toISOString() ? pill('crit', 'Expired') : fmtDate(t.expires_at)) : 'Never') },
        { key: 'last_used_at', label: 'Last used', render: (t) => (t.last_used_at ? `${ago(t.last_used_at)}<div class="cell-sub mono">${esc(t.last_ip || '')}</div>` : '<span class="muted">Never</span>') },
        { key: 'x', label: '', render: (t) => (t.revoked ? pill('', 'Revoked') : `<button class="btn sm danger" data-revoke="${t.id}">Revoke</button>`) }], tokens, { empty: 'No API tokens' })}</div>`;

  const collect = (scope) => { const o = {}; $$(`${scope} [data-sk]`).forEach((el) => { o[el.dataset.sk] = el.type === 'checkbox' ? (el.checked ? '1' : '0') : el.value; }); return o; };
  const cardOf = (id) => $(`#${id}`).closest('.card');
  $('#saveAccess').onclick = guard(async () => { await api('PUT', '/api/security', collect('#' + (cardOf('saveAccess').id = 'cAccess'))); toast('Access policy saved'); reload(); });
  $$('[data-sk="uninstall_protection"]').forEach((el) => el.onchange = guard(async () => { await api('PUT', '/api/security', { uninstall_protection: el.checked ? '1' : '0' }); toast(el.checked ? 'Uninstall protection on' : 'Uninstall protection off'); reload(); }));
  if ($('#showCode')) $('#showCode').onclick = () => { const c = $('#ucode'); c.textContent = c.textContent.includes('•') ? c.dataset.code.replace(/(\d{4})(\d{4})/, '$1 $2') : '•••• ••••'; };
  if ($('#rotCode')) $('#rotCode').onclick = guard(async () => { if (await confirmBox('Rotate the uninstall code? The old code stops working once devices check in.')) { await api('POST', '/api/security/uninstall-code'); reload(); } });
  $('#saveHook').onclick = guard(async () => {
    const body = collect('#' + (cardOf('saveHook').id = 'cHook'));
    if ($('#whUrl').value.trim()) body.webhook_url = $('#whUrl').value.trim();
    if ($('#whSecret').value) body.webhook_secret = $('#whSecret').value;
    await api('PUT', '/api/security', body); toast('Notification settings saved'); reload();
  });
  $('#testHook').onclick = guard(async () => { await api('POST', '/api/security/webhook-test'); toast('Test notification delivered'); reload(); });
  if ($('#clearHook')) $('#clearHook').onclick = guard(async () => { await api('PUT', '/api/security', { webhook_url: '', webhook_secret: '' }); reload(); });
  $('#doBackup').onclick = guard(async () => {
    const pass = $('#bkPass').value;
    if (pass.length < 12) throw new Error('Passphrase must be at least 12 characters');
    const res = await fetch('/api/admin/backup', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'fetch' }, body: JSON.stringify({ passphrase: pass }) });
    if (!res.ok) throw new Error((await res.json()).error || 'Backup failed');
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement('a'); a.href = url; a.download = `asset-portal-${new Date().toISOString().slice(0, 10)}.apbak`; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 5000); $('#bkPass').value = ''; toast('Encrypted backup downloaded');
  });
  $('#verifyAudit').onclick = guard(async () => { const r = await GET('/api/audit/verify'); $('#verifyOut').innerHTML = r.ok ? `<span style="color:var(--ok)">✓ ${fmtNum(r.checked)} entries intact</span>` : `<span style="color:var(--crit)">✗ Chain broken at entry #${r.broken_at}</span>`; });
  $('#newTok').onclick = () => formModal({
    title: 'New API token', submitLabel: 'Create token', values: { role: 'viewer', days: 90 },
    fields: [{ name: 'name', label: 'Name', required: true, full: true, placeholder: 'e.g. Power BI dashboard' },
      { name: 'role', label: 'Access', type: 'select', blank: false, options: [{ value: 'viewer', label: 'Read-only' }, { value: 'tech', label: 'Read & write assets' }] },
      { name: 'days', label: 'Expires after (days, 0 = never)', type: 'number' }],
    onSubmit: async (val) => {
      const r = await api('POST', '/api/tokens', val);
      modal({ title: 'Copy your token now', body: `${callout('warn', 'This is the only time the token is shown. Store it in your secret manager.')}<pre class="cmd">${esc(r.token)}</pre><div class="copy-row"><button class="btn sm" data-copy="${esc(r.token)}">${icon('copy', 'sm')} Copy</button></div>` });
      reload();
    },
  });
  $$('[data-revoke]').forEach((b) => b.onclick = guard(async () => { if (await confirmBox('Revoke this token? Integrations using it stop working immediately.')) { await api('DELETE', `/api/tokens/${b.dataset.revoke}`); reload(); } }));
});

// ------------------------------------------------------------------ check-out (person or location) & physical audit
function checkoutModal(asset) {
  const due = new Date(Date.now() + 14 * 86400000).toISOString().slice(0, 10);
  const m = modal({
    title: `Check out ${asset.name}`, submitLabel: 'Check out',
    body: `<div class="seg" role="tablist"><button type="button" class="active" data-to="person">${icon('users', 'sm')} To a person</button><button type="button" data-to="location">${icon('pin', 'sm')} To a location</button></div>
      <div class="form-grid" style="margin-top:14px">
        <div class="field full" data-for="person"><label>Person</label><select name="person_id"><option value="">— choose —</option>${S.meta.people.map((p) => `<option value="${p.id}">${esc(p.name)}${p.email ? ` (${esc(p.email)})` : ''}</option>`).join('')}</select></div>
        <div class="field full" data-for="location" hidden><label>Location</label><select name="location_id"><option value="">— choose —</option>${S.meta.locations.map((l) => `<option value="${l.id}">${esc(l.name)}</option>`).join('')}</select></div>
        <div class="field"><label>Due back</label><input type="date" name="due_at" value="${due}"></div>
        <div class="field full"><label>Notes</label><textarea name="notes" placeholder="Purpose, accessories handed over…"></textarea></div>
      </div><p class="small muted">If acceptance is required and the person has a self-service login, they are asked to accept and sign for the equipment.</p>`,
    onSubmit: async (form) => {
      const v = formValues(form);
      const to = $('.seg .active', form).dataset.to;
      if (to === 'person') delete v.location_id; else delete v.person_id;
      if (!v.person_id && !v.location_id) throw new Error(`Choose a ${to}`);
      await api('POST', asset.ids ? '/api/assets/bulk-checkout' : `/api/assets/${asset.id}/checkout`, asset.ids ? { ...v, ids: asset.ids } : v).then((r) => {
        if (r.errors?.length) toast(`${r.count} checked out — ${r.errors.length} skipped: ${r.errors[0]}`, true); else toast('Checked out');
      });
      await refreshMeta(); reload();
    },
  });
  $$('.seg button', m).forEach((b) => b.onclick = () => {
    $$('.seg button', m).forEach((x) => x.classList.toggle('active', x === b));
    $$('[data-for]', m).forEach((f) => { f.hidden = f.dataset.for !== b.dataset.to; });
  });
}
function auditModal(asset) {
  formModal({
    title: asset.ids ? `Audit ${asset.ids.length} assets` : `Audit ${asset.name}`, submitLabel: 'Record audit',
    values: { location_id: asset.location_id || '' },
    fields: [{ name: 'location_id', label: 'Found at location', type: 'select', options: opts(S.meta.locations), help: 'Leave empty to keep the current location.' },
      { name: 'next_audit_date', label: 'Next audit due', type: 'date', help: 'Default: today + the audit interval in Settings.' },
      { name: 'notes', label: 'Notes', type: 'textarea', full: true, placeholder: 'Condition, who it was with…' }],
    onSubmit: async (v) => { await api('POST', asset.ids ? '/api/assets/bulk-audit' : `/api/assets/${asset.id}/audit`, asset.ids ? { ...v, ids: asset.ids } : v); toast('Audit recorded'); reload(); },
  });
}

// ------------------------------------------------------------------ stock: accessories, consumables, components
const KIND_LABEL = { accessory: 'Accessory', consumable: 'Consumable', component: 'Component' };
const STOCK_FIELDS = () => [
  { name: 'name', label: 'Item name', required: true, full: true },
  { name: 'kind', label: 'Kind', type: 'select', blank: false, options: Object.entries(KIND_LABEL).map(([value, label]) => ({ value, label })), help: 'Consumables are used up; accessories and components are returned.' },
  { name: 'category', label: 'Category', placeholder: 'e.g. Keyboards, Toner, RAM' },
  { name: 'manufacturer', label: 'Manufacturer' }, { name: 'model_number', label: 'Model / part number' },
  { name: 'qty_total', label: 'Quantity in stock', type: 'number' }, { name: 'min_qty', label: 'Alert when available ≤', type: 'number' },
  { name: 'location_id', label: 'Stored at', type: 'select', options: opts(S.meta.locations) }, { name: 'supplier', label: 'Supplier' },
  { name: 'unit_cost', label: 'Unit cost', type: 'number' }, { name: 'notes', label: 'Notes', type: 'textarea', full: true },
];
const stockBar = (s) => `<div class="stockbar" title="${s.available} available of ${s.qty_total}"><span style="width:${s.qty_total ? Math.max(0, (s.available / s.qty_total) * 100) : 0}%" class="${s.low ? 'low' : ''}"></span></div>`;
route(/^\/stock$/, async (v, q) => {
  const kind = q.kind || '';
  const rows = await GET(`/api/stock?${qs({ kind, q: q.q, low: q.low })}`);
  const tabs = [['', 'All'], ['accessory', 'Accessories'], ['consumable', 'Consumables'], ['component', 'Components']]
    .map(([k, l]) => `<a class="btn ${kind === k && !q.low ? 'primary' : ''}" href="#/stock${k ? `?kind=${k}` : ''}">${l}</a>`).join('') + `<a class="btn ${q.low ? 'primary' : ''}" href="#/stock?low=1">${icon('alert', 'sm')} Low stock</a>`;
  v.innerHTML = head('Accessories &amp; stock', can('tech') ? `<button class="btn primary" id="newStock">${icon('plus', 'sm')} Add item</button>` : '', '', 'Quantity-tracked items: keyboards, docks, cables, toner, spare parts.')
    + `<div class="filters">${tabs}<span style="margin-left:auto"></span><input type="search" id="sq" placeholder="Search items…" value="${esc(q.q || '')}"></div>`
    + table([
      { key: 'name', label: 'Item', render: (s) => `<a class="cell-main" href="#/stock/${s.id}">${esc(s.name)}</a><div class="cell-sub">${esc([s.manufacturer, s.model_number].filter(Boolean).join(' · '))}</div>` },
      { key: 'kind', render: (s) => pill(s.kind === 'consumable' ? 'warn' : s.kind === 'component' ? 'info' : '', KIND_LABEL[s.kind]) },
      { key: 'category' }, { key: 'location' },
      { key: 'available', label: 'Available', render: (s) => `<div style="display:flex;align-items:center;gap:10px"><b class="${s.low ? 'neg' : ''}">${s.available}</b><span class="muted small">/ ${s.qty_total}</span>${stockBar(s)}</div>` },
      { key: 'checked_out', label: 'Out', num: true }, { key: 'min_qty', label: 'Min', num: true },
      ...(hasPerm('stock.checkout') ? [{ key: 'x', label: '', render: (s) => (s.available > 0 ? `<button class="btn sm" data-co="${s.id}">${s.kind === 'consumable' ? 'Issue' : 'Check out'}</button>` : '<span class="muted small">Out of stock</span>') }] : []),
    ], rows, { empty: 'No items yet. Add accessories or consumables, or import them from CSV.' });
  let t;
  $('#sq').oninput = (e) => { clearTimeout(t); t = setTimeout(() => { location.hash = `#/stock?${qs({ kind, q: e.target.value })}`; }, 400); };
  if ($('#newStock')) $('#newStock').onclick = () => formModal({ title: 'Add stock item', fields: STOCK_FIELDS(), values: { kind: kind || 'accessory', qty_total: 1, min_qty: 0 },
    onSubmit: async (val) => { const r = await api('POST', '/api/stock', val); location.hash = `#/stock/${r.id}`; } });
  $$('[data-co]').forEach((b) => b.onclick = () => stockCheckoutModal(rows.find((s) => s.id === Number(b.dataset.co))));
});
function stockCheckoutModal(s) {
  formModal({
    title: `${s.kind === 'consumable' ? 'Issue' : 'Check out'} ${s.name}`, submitLabel: s.kind === 'consumable' ? 'Issue' : 'Check out', values: { qty: 1 },
    fields: [{ name: 'person_id', label: 'To', type: 'select', required: true, options: opts(S.meta.people), full: true },
      { name: 'qty', label: `Quantity (${s.available} available)`, type: 'number', required: true }, { name: 'notes', label: 'Notes', full: true }],
    onSubmit: async (v) => { await api('POST', `/api/stock/${s.id}/checkout`, v); toast(s.kind === 'consumable' ? 'Issued' : 'Checked out'); reload(); },
  });
}
route(/^\/stock\/(\d+)$/, async (v, q, id) => {
  const s = await GET(`/api/stock/${id}`);
  const act = { restock: 'Restocked', writeoff: 'Written off', checkout: 'Checked out', checkin: 'Returned', consume: 'Issued', adjust: 'Adjusted' };
  v.innerHTML = head(`${esc(s.name)} ${pill(s.kind === 'consumable' ? 'warn' : s.kind === 'component' ? 'info' : '', KIND_LABEL[s.kind])}`,
    `${hasPerm('stock.checkout') && s.available > 0 ? `<button class="btn primary" id="sCo">${icon('tag', 'sm')} ${s.kind === 'consumable' ? 'Issue' : 'Check out'}</button>` : ''}
     ${can('tech') ? `<button class="btn" id="sRe">${icon('plus', 'sm')} Restock / write off</button><button class="btn" id="sEd">Edit</button><button class="btn danger" id="sDel">Delete</button>` : ''}`,
    '<a href="#/stock">Accessories &amp; stock</a>') + `
    ${s.low ? callout('warn', `Only <b>${s.available}</b> available — at or below the minimum of ${s.min_qty}.`) : ''}
    <div class="kpis">
      <div class="kpi ${s.low ? 'warn' : 'ok'}"><span class="chip">${icon('box')}</span><div><div class="v">${s.available}</div><div class="l">Available</div></div></div>
      <div class="kpi"><span class="chip">${icon('users')}</span><div><div class="v">${s.checked_out}</div><div class="l">Checked out</div></div></div>
      <div class="kpi"><span class="chip">${icon('layers')}</span><div><div class="v">${s.qty_total}</div><div class="l">Total owned</div></div></div>
      <div class="kpi"><span class="chip">${icon('dollar')}</span><div><div class="v" style="font-size:18px">${money((s.unit_cost || 0) * s.qty_total)}</div><div class="l">Stock value</div></div></div>
    </div>
    <div class="grid g2" style="margin-bottom:18px">
      <div class="card"><div class="card-head"><h2>Details</h2></div><dl class="kv"><dt>Category</dt><dd>${esc(s.category || '—')}</dd><dt>Manufacturer</dt><dd>${esc(s.manufacturer || '—')}</dd>
        <dt>Model / part #</dt><dd>${esc(s.model_number || '—')}</dd><dt>Stored at</dt><dd>${esc(s.location || '—')}</dd><dt>Supplier</dt><dd>${esc(s.supplier || '—')}</dd>
        <dt>Unit cost</dt><dd>${money(s.unit_cost)}</dd><dt>Minimum</dt><dd>${s.min_qty}</dd><dt>Notes</dt><dd>${esc(s.notes || '')}</dd></dl></div>
      <div class="card"><div class="card-head"><h2>Currently held by</h2></div>${table([{ key: 'person', render: (h) => (h.person_id ? `<a href="#/people/${h.person_id}">${esc(h.person)}</a>` : '—') },
        { key: 'qty', num: true }, { key: 'ts', label: 'Since', render: (h) => fmtDate(h.ts) },
        ...(hasPerm('stock.checkout') ? [{ key: 'x', label: '', render: (h) => `<button class="btn sm" data-ci="${h.id}">Check in</button>` }] : [])], s.holders, { empty: s.kind === 'consumable' ? 'Consumables are issued, not held.' : 'Nobody holds this item' })}</div>
    </div>
    <div class="card"><div class="card-head"><h2>Movement history</h2></div>${table([{ key: 'ts', label: 'When', render: (m) => fmtDT(m.ts) },
      { key: 'action', render: (m) => pill(m.action === 'restock' ? 'ok' : m.action === 'writeoff' ? 'crit' : m.action === 'checkin' ? 'info' : '', act[m.action] || m.action) },
      { key: 'qty', num: true, render: (m) => (m.qty > 0 && ['restock', 'adjust'].includes(m.action) ? `+${m.qty}` : m.qty) }, { key: 'person', render: (m) => esc(m.person || '') },
      { key: 'by_user', label: 'By' }, { key: 'notes', render: (m) => `<span class="small">${esc(m.notes || '')}</span>` }], s.moves)}</div>`;
  if ($('#sCo')) $('#sCo').onclick = () => stockCheckoutModal(s);
  $$('[data-ci]').forEach((b) => b.onclick = guard(async () => { await api('POST', `/api/stock/${id}/checkin`, { move_id: Number(b.dataset.ci) }); toast('Returned to stock'); reload(); }));
  if ($('#sRe')) $('#sRe').onclick = () => formModal({ title: 'Restock or write off', submitLabel: 'Save',
    fields: [{ name: 'qty', label: 'Quantity (+ received, − lost/broken)', type: 'number', required: true, full: true }, { name: 'notes', label: 'Reason / PO number', full: true }],
    onSubmit: async (val) => { await api('POST', `/api/stock/${id}/restock`, val); toast('Stock updated'); reload(); } });
  if ($('#sEd')) $('#sEd').onclick = () => formModal({ title: 'Edit item', fields: STOCK_FIELDS(), values: s, onSubmit: async (val) => { await api('PUT', `/api/stock/${id}`, val); reload(); } });
  if ($('#sDel')) $('#sDel').onclick = guard(async () => { if (await confirmBox('Delete this item and its history?')) { await api('DELETE', `/api/stock/${id}`); location.hash = '#/stock'; } });
});

// ------------------------------------------------------------------ import centre (stored files + field mapping)
const IMPORT_HELP = {
  assets: 'Company, Name, Serial, Asset Tag, Manufacturer, Model, Model Number, Category, Status, Location, Order Number, Supplier, Purchase Date, Purchase Cost, Checkout Type, Checked Out To (username / first / last / email), Checkout Location, Asset EOL Date, plus any custom field.',
  people: 'First Name, Last Name (or Full Name), Email, Username, Employee Number, Job Title, Phone, Department, Location, Company.',
  users: 'Same as People plus Activated (yes/no), Role (user/viewer/tech) and optional Password. Activated users get a self-service login; generated passwords are shown once after import.',
  accessories: 'Item Name, Category, Manufacturer, Model Number, Qty, Min Amt, Purchase Cost, Supplier, Location, Order Number, Purchase Date.',
  consumables: 'Item Name, Category, Manufacturer, Model Number, Qty, Min Amt, Purchase Cost, Supplier, Location.',
  components: 'Item Name, Category, Manufacturer, Model/Part Number, Qty, Min Amt, Purchase Cost, Supplier, Location.',
  licenses: 'Name, Product Key, Seats, Manufacturer, License Type, Purchase Date, Expiration Date, Purchase Cost, Order Number, Notes.',
  locations: 'Name, Address, City, State, Postal Code, Country, Latitude, Longitude.',
};
const IMPORT_TEMPLATES = {
  assets: 'Company,Name,Serial,Asset Tag,Manufacturer,Model,Model Number,Category,Status,Location,Order Number,Supplier,Purchase Date,Purchase Cost,Checkout Type,Checked Out To: Email,Checkout Location,Asset EOL Date\nAcme Ltd,Laptop,5CG1234XYZ,AST-1001,Dell,Latitude,7440,Laptops,Deployed,Head Office,PO-2026-001,Redington,11-Sep-26,"85,000",user,jane@company.com,,11-Sep-30\n',
  people: 'First Name,Last Name,Email,Username,Employee Number,Job Title,Department,Location,Company\nJane,Doe,jane@company.com,jdoe,E1001,Accountant,Finance,Head Office,Acme Ltd\n',
  users: 'First Name,Last Name,Email,Username,Department,Location,Activated,Role\nJane,Doe,jane@company.com,jdoe,Finance,Head Office,yes,user\n',
  accessories: 'Item Name,Category,Manufacturer,Model Number,Qty,Min Amt,Purchase Cost,Location\nUSB-C Dock,Docks,Dell,WD19,20,5,18000,Head Office\n',
  consumables: 'Item Name,Category,Model Number,Qty,Min Amt,Purchase Cost\nToner,Printer supplies,CF226A,12,3,4500\n',
  components: 'Item Name,Category,Manufacturer,Model Number,Qty,Min Amt\n16GB DDR5 SODIMM,Memory,Kingston,KVR48S40BS8-16,30,5\n',
  licenses: 'Name,Product Key,Seats,Manufacturer,License Type,Purchase Date,Expiration Date,Purchase Cost\nMicrosoft 365 E3,,50,Microsoft,per_user,01-Apr-26,31-Mar-27,"4,50,000"\n',
  locations: 'Name,Address,City,State,Postal Code,Country,Latitude,Longitude\nHead Office,Sector 62,Noida,UP,201309,India,28.627,77.373\n',
};
const fmtSize = (b) => (b > 1048576 ? `${(b / 1048576).toFixed(1)} MB` : `${(b / 1024).toFixed(2)} KB`);
route(/^\/import$/, async (v, q) => {
  const [types, files] = await Promise.all([GET('/api/import/types'), GET('/api/import/files')]);
  const open = Number(q.file) || null;
  v.innerHTML = `<div class="import-layout"><div>
    ${head('Import', `<input type="file" id="upFile" accept=".csv,text/csv" hidden multiple><button class="btn primary" id="upBtn">${icon('upload', 'sm')} Select file…</button>`, '', 'Upload a CSV, map its columns, preview, then import.')}
    <div class="card" style="padding:0">${files.length ? `<div class="table-wrap" style="border:none;box-shadow:none"><table class="imp-files"><thead><tr><th>File name</th><th>Uploaded</th><th class="num">Rows</th><th class="num">Size</th><th>Last import</th><th></th></tr></thead><tbody>
      ${files.map((f) => `<tr class="${open === f.id ? 'sel' : ''}"><td><b>${esc(f.name)}</b><div class="cell-sub">by ${esc(f.created_by || '')}</div></td><td>${fmtDT(f.created_at)}</td>
        <td class="num">${fmtNum(f.rows)}</td><td class="num">${fmtSize(f.size)}</td>
        <td class="small">${f.last_result ? `${esc(types[f.last_result.type] || f.last_result.type)}: <b style="color:var(--ok)">${f.last_result.created}</b> new · ${f.last_result.updated} updated${f.last_result.errors ? ` · <b style="color:var(--crit)">${f.last_result.errors} errors</b>` : ''}<div class="cell-sub">${ago(f.last_run_at)}</div>` : '<span class="muted">Not imported yet</span>'}</td>
        <td style="white-space:nowrap"><button class="btn sm ${open === f.id ? '' : 'primary'}" data-proc="${f.id}">${icon('list', 'sm')} ${open === f.id ? 'Close' : 'Process'}</button> <button class="btn sm danger" data-delf="${f.id}" title="Delete file">${icon('trash', 'sm')}</button></td></tr>
        ${open === f.id ? `<tr class="imp-panel-row"><td colspan="6"><div id="impPanel" class="imp-panel"><div class="empty">Reading file…</div></div></td></tr>` : ''}`).join('')}
      </tbody></table></div>` : `<div class="empty" style="padding:56px 20px">${icon('upload')}<div><b>No files yet</b></div><div class="small">Click <b>Select file…</b> to upload a CSV exported from Excel, Snipe-IT or another tool.</div></div>`}</div>
  </div>
  <aside class="import-help card"><h2>Importing</h2>
    <p class="small">You can import <b>assets, people, users, accessories, consumables, components, licenses</b> and <b>locations</b> from CSV. The first row must contain the column names — they don't need to match ours; you map them in the next step.</p>
    <p class="small muted">Dates like <span class="mono">11-Sep-26</span>, <span class="mono">13/05/2026</span>, <span class="mono">2026-05-13</span> and Excel date numbers are understood. Amounts like <span class="mono">4,50,000</span>, <span class="mono">₹58,500</span> or <span class="mono">1.2 lakh</span> work too.</p>
    <p class="small muted">Missing companies, models, manufacturers, categories, suppliers, locations and people are created automatically.</p>
    <h3>Sample CSVs</h3>${Object.entries(types).map(([k, l]) => `<button class="dd-item small" data-tpl="${k}">${icon('download', 'sm')} ${esc(l)}</button>`).join('')}
  </aside></div>`;

  $('#upBtn').onclick = () => $('#upFile').click();
  $('#upFile').onchange = guard(async (e) => {
    let last;
    for (const f of e.target.files) {
      if (f.size > 25 * 1024 * 1024) throw new Error(`${f.name} is larger than 25 MB`);
      last = await api('POST', '/api/import/files', { name: f.name, csv: await f.text() });
    }
    toast('File uploaded'); location.hash = `#/import?file=${last.id}`;
  });
  $$('[data-tpl]').forEach((b) => b.onclick = () => { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([IMPORT_TEMPLATES[b.dataset.tpl]], { type: 'text/csv' })); a.download = `sample-${b.dataset.tpl}.csv`; a.click(); });
  $$('[data-proc]').forEach((b) => b.onclick = () => { location.hash = open === Number(b.dataset.proc) ? '#/import' : `#/import?file=${b.dataset.proc}`; });
  $$('[data-delf]').forEach((b) => b.onclick = guard(async () => { if (await confirmBox('Delete this uploaded file?')) { await api('DELETE', `/api/import/files/${b.dataset.delf}`); location.hash = '#/import'; reload(); } }));
  if (open) await renderImportPanel(open, types, q.type);
});

async function renderImportPanel(fileId, types, typeArg) {
  const panel = $('#impPanel');
  const d = await GET(`/api/import/files/${fileId}/analyse?${qs({ type: typeArg || '' })}`);
  const mapping = { ...d.guess };
  const groups = [...new Set(d.fields.map((f) => f.group))];
  const optionsFor = (h) => `<option value="">Do Not Import</option>${groups.map((g) => `<optgroup label="${esc(g)}">${d.fields.filter((f) => f.group === g).map((f) => `<option value="${esc(f.key)}" ${mapping[h] === f.key ? 'selected' : ''}>${esc(f.label)}</option>`).join('')}</optgroup>`).join('')}
    ${d.type === 'assets' ? `<optgroup label="Custom fields"><option value="newcf" ${mapping[h] === 'newcf' ? 'selected' : ''}>+ New custom field "${esc(h)}"</option></optgroup>` : ''}`;
  const mapped = () => Object.values(mapping).filter(Boolean).length;
  panel.innerHTML = `<div class="imp-opts">
      <div class="field"><label>CSV import type</label><select id="impType">${Object.entries(types).map(([k, l]) => `<option value="${k}" ${d.type === k ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select></div>
      <div class="field"><label>Dates in this file are</label><select id="impDate"><option value="DMY">Day/Month/Year (11/09/2026)</option><option value="MDY">Month/Day/Year (09/11/2026)</option></select></div>
      <div class="imp-checks"><label><input type="checkbox" id="impUpd" checked> Update existing values?</label>
        <label><input type="checkbox" id="impBak" checked> Backup before importing?</label>
        ${d.type === 'users' ? '<label class="muted"><input type="checkbox" disabled> Send welcome email <span class="small">(no mail server configured — passwords are shown after import instead)</span></label>' : ''}</div>
    </div>
    <h2 class="imp-title">${icon('list')} Map ${esc(types[d.type])} fields <span class="muted small" id="mapCount">${mapped()} of ${d.headers.length} columns mapped · ${fmtNum(d.total)} rows</span></h2>
    <div class="imp-map"><div class="imp-map-head"><span>CSV header field</span><span>Import field</span><span>Sample value</span></div>
      ${d.headers.map((h) => `<div class="imp-map-row ${mapping[h] ? 'on' : ''}"><b title="${esc(h)}">${esc(h)}</b><select data-h="${esc(h)}">${optionsFor(h)}</select><span class="sample" title="${esc(d.sample[h])}">${esc(d.sample[h] || '')}</span></div>`).join('')}
    </div>
    <div class="imp-actions"><a href="#/import" class="btn ghost">Cancel</a><span style="flex:1"></span>
      <button class="btn" id="impDry">${icon('eye', 'sm')} Preview (dry run)</button><button class="btn primary" id="impRun">${icon('check', 'sm')} Process import</button></div>
    <div id="impRes"></div>`;
  $('#impType').onchange = (e) => { location.hash = `#/import?file=${fileId}&type=${e.target.value}`; };
  $$('[data-h]', panel).forEach((sel) => sel.onchange = () => {
    if (sel.value && sel.value !== 'newcf') {
      for (const [k, val] of Object.entries(mapping)) if (val === sel.value && k !== sel.dataset.h) { mapping[k] = ''; const o = $(`[data-h="${CSS.escape(k)}"]`, panel); o.value = ''; o.closest('.imp-map-row').classList.remove('on'); }
    }
    mapping[sel.dataset.h] = sel.value;
    sel.closest('.imp-map-row').classList.toggle('on', !!sel.value);
    $('#mapCount').textContent = `${mapped()} of ${d.headers.length} columns mapped · ${fmtNum(d.total)} rows`;
  });
  const run = (dry) => guard(async () => {
    const btn = dry ? $('#impDry') : $('#impRun');
    btn.disabled = true;
    try {
      const body = { type: d.type, mapping: Object.fromEntries(Object.entries(mapping).filter(([, x]) => x)), update_existing: $('#impUpd').checked, backup: $('#impBak').checked, date_format: $('#impDate').value, dry_run: dry };
      const r = await api('POST', `/api/import/files/${fileId}/run`, body);
      const catalog = Object.entries(r.catalog || {}).map(([k, n]) => `${n} ${k.replace('_', ' ')}`).join(', ');
      $('#impRes').innerHTML = `<div class="imp-result ${r.error_count ? 'warn' : 'ok'}"><h3 style="margin-top:0">${dry ? 'Dry run — nothing was saved' : 'Import finished'}</h3>
        <div class="facts" style="margin:8px 0 12px"><div><small>Rows</small><b>${fmtNum(r.total)}</b></div><div><small>${dry ? 'Would create' : 'Created'}</small><b style="color:var(--ok)">${r.created}</b></div>
          <div><small>${dry ? 'Would update' : 'Updated'}</small><b>${r.updated}</b></div><div><small>Skipped</small><b>${r.skipped}</b></div>
          ${d.type === 'assets' ? `<div><small>Checked out</small><b>${r.checked_out}</b></div>` : ''}<div><small>Errors</small><b style="color:${r.error_count ? 'var(--crit)' : 'inherit'}">${r.error_count}</b></div></div>
        ${catalog ? `<p class="small">${dry ? 'Would also create' : 'Also created'}: ${esc(catalog)}.</p>` : ''}
        ${r.backup ? `<p class="small muted">${icon('shieldCheck', 'sm')} Backup saved on the server as <span class="mono">data\\backups\\${esc(r.backup)}</span></p>` : ''}
        ${r.errors.length ? table([{ key: 'row', label: 'CSV row', num: true }, { key: 'value', label: 'Record', render: (e) => `<span class="small">${esc(e.value || '')}</span>` }, { key: 'error', label: 'Problem' }], r.errors) : callout('ok', dry ? 'No problems found — click <b>Process import</b> to save.' : 'All rows imported successfully.')}
        ${r.credentials?.length ? `${callout('warn', `<b>${r.credentials.length} login(s) created.</b> Download the initial passwords now — they are not shown again. Users must change them at first sign-in.`)}<button class="btn" id="credDl">${icon('download', 'sm')} Download passwords (CSV)</button>` : ''}
        ${!dry ? `<p style="margin-top:12px"><a class="btn" href="#/${{ people: 'people', users: 'users', accessories: 'stock', consumables: 'stock?kind=consumable', components: 'stock?kind=component', licenses: 'licenses', locations: 'locations' }[d.type] || 'assets'}">Open ${esc(types[d.type])}</a></p>` : ''}</div>`;
      if ($('#credDl')) $('#credDl').onclick = () => {
        const csv = 'username,name,role,initial_password\n' + r.credentials.map((x) => [x.username, x.name, x.role, x.password].map((y) => `"${String(y).replace(/"/g, '""')}"`).join(',')).join('\n');
        const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' })); a.download = 'initial-passwords.csv'; a.click();
      };
      if (!dry) { await refreshMeta(); toast(`Imported: ${r.created} created, ${r.updated} updated`); }
      $('#impRes').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    } finally { btn.disabled = false; }
  });
  $('#impDry').onclick = run(true);
  $('#impRun').onclick = run(false);
}

// ------------------------------------------------------------------ catalog: models, categories, manufacturers, suppliers, companies
const CATALOG = {
  models: { title: 'Asset models', icon: 'monitor', fields: () => [{ name: 'name', label: 'Model name', required: true }, { name: 'model_number', label: 'Model number' },
    { name: 'manufacturer_id', label: 'Manufacturer', type: 'select', options: opts(S.meta.manufacturers) },
    { name: 'category_id', label: 'Category', type: 'select', options: opts(S.meta.categories.filter((c) => c.kind === 'asset')) },
    { name: 'asset_type', label: 'Asset type', type: 'select', options: opts(S.meta.types) }, { name: 'eol_months', label: 'End of life (months)', type: 'number' },
    { name: 'notes', label: 'Notes', type: 'textarea', full: true }],
    cols: [{ key: 'name', render: (m) => `<b>${esc(m.name)}</b><div class="cell-sub">${esc(m.model_number || '')}</div>` }, { key: 'manufacturer' }, { key: 'category' },
      { key: 'asset_type', label: 'Type', render: (m) => titleCase(m.asset_type || '') }, { key: 'eol_months', label: 'EOL', render: (m) => (m.eol_months ? `${m.eol_months} mo` : '') },
      { key: 'assets', num: true, render: (m) => `<a href="#/assets?model_id=${m.id}">${m.assets}</a>` }] },
  categories: { title: 'Categories', icon: 'layers', fields: () => [{ name: 'name', label: 'Name', required: true },
    { name: 'kind', label: 'Used for', type: 'select', blank: false, options: [{ value: 'asset', label: 'Assets' }, { value: 'accessory', label: 'Accessories' }, { value: 'consumable', label: 'Consumables' }, { value: 'component', label: 'Components' }, { value: 'license', label: 'Licenses' }] },
    { name: 'notes', label: 'Notes', type: 'textarea', full: true }],
    cols: [{ key: 'name', render: (c) => `<b>${esc(c.name)}</b>` }, { key: 'kind', label: 'Used for', render: (c) => pill('', titleCase(c.kind)) }, { key: 'models', num: true },
      { key: 'assets', num: true, render: (c) => (c.kind === 'asset' ? `<a href="#/assets?category_id=${c.id}">${c.assets}</a>` : '') }, { key: 'items', label: 'Stock items', num: true }] },
  manufacturers: { title: 'Manufacturers', icon: 'building', fields: () => [{ name: 'name', label: 'Name', required: true }, { name: 'url', label: 'Website' },
    { name: 'support_url', label: 'Support URL' }, { name: 'support_email', label: 'Support email', type: 'email' }, { name: 'support_phone', label: 'Support phone' }, { name: 'notes', label: 'Notes', type: 'textarea', full: true }],
    cols: [{ key: 'name', render: (m) => `<b>${esc(m.name)}</b>${m.url ? `<div class="cell-sub">${esc(m.url)}</div>` : ''}` },
      { key: 'support', label: 'Support', render: (m) => `${m.support_url ? `<a href="${esc(m.support_url)}" target="_blank" rel="noopener">Portal</a> ` : ''}<span class="small">${esc([m.support_email, m.support_phone].filter(Boolean).join(' · '))}</span>` },
      { key: 'models', num: true }, { key: 'assets', num: true }] },
  suppliers: { title: 'Suppliers', icon: 'tag', fields: () => [{ name: 'name', label: 'Name', required: true }, { name: 'contact', label: 'Contact person' }, { name: 'email', label: 'Email', type: 'email' },
    { name: 'phone', label: 'Phone' }, { name: 'url', label: 'Website' }, { name: 'address', label: 'Address', full: true }, { name: 'notes', label: 'Notes', type: 'textarea', full: true }],
    cols: [{ key: 'name', render: (s) => `<b>${esc(s.name)}</b>` }, { key: 'contact' }, { key: 'email' }, { key: 'phone' }, { key: 'assets', num: true, render: (s) => `<a href="#/assets?supplier_id=${s.id}">${s.assets}</a>` }] },
  companies: { title: 'Companies', icon: 'building', fields: () => [{ name: 'name', label: 'Company name', required: true }, { name: 'phone', label: 'Phone' }, { name: 'email', label: 'Email', type: 'email' }, { name: 'notes', label: 'Notes', type: 'textarea', full: true }],
    cols: [{ key: 'name', render: (c) => `<b>${esc(c.name)}</b>` }, { key: 'email' }, { key: 'phone' },
      { key: 'assets', num: true, render: (c) => `<a href="#/assets?company_id=${c.id}">${c.assets}</a>` }, { key: 'people', num: true }] },
};
route(/^\/catalog(?:\/(\w+))?$/, async (v, q, kind = 'models') => {
  const def = CATALOG[kind] || CATALOG.models;
  const rows = await GET(`/api/${kind}`);
  const filter = (q.q || '').toLowerCase();
  const shown = filter ? rows.filter((r) => JSON.stringify(r).toLowerCase().includes(filter)) : rows;
  v.innerHTML = head('Catalog', can('tech') ? `<button class="btn primary" id="catNew">${icon('plus', 'sm')} New ${esc(def.title.replace(/ies$/, 'y').replace(/s$/, '').toLowerCase())}</button>` : '', '',
    'Reference data used across assets, stock and licenses — the importer fills it automatically.')
    + `<div class="tabs">${Object.entries(CATALOG).map(([k, c]) => `<button data-cat="${k}" class="${k === kind ? 'active' : ''}">${c.title}</button>`).join('')}</div>
    <div class="filters"><input type="search" id="catQ" placeholder="Filter ${esc(def.title.toLowerCase())}…" value="${esc(q.q || '')}"><span class="muted small">${shown.length} of ${rows.length}</span></div>`
    + table([...def.cols, ...(can('tech') ? [{ key: 'x', label: '', render: (r) => `<button class="btn sm" data-ce="${r.id}">Edit</button> <button class="btn sm danger" data-cd="${r.id}">Delete</button>` }] : [])], shown,
      { empty: `No ${def.title.toLowerCase()} yet. They are created automatically when you import, or add one manually.` });
  $$('[data-cat]').forEach((b) => b.onclick = () => { location.hash = `#/catalog/${b.dataset.cat}`; });
  let t;
  $('#catQ').oninput = (e) => { clearTimeout(t); t = setTimeout(() => { location.hash = `#/catalog/${kind}?${qs({ q: e.target.value })}`; }, 350); };
  const save = (id) => async (val) => { await api(id ? 'PUT' : 'POST', id ? `/api/${kind}/${id}` : `/api/${kind}`, val); await refreshMeta(); toast('Saved'); reload(); };
  if ($('#catNew')) $('#catNew').onclick = () => formModal({ title: `New ${def.title.replace(/ies$/, 'y').replace(/s$/, '').toLowerCase()}`, fields: def.fields(), values: kind === 'categories' ? { kind: 'asset' } : {}, onSubmit: save(null) });
  $$('[data-ce]').forEach((b) => b.onclick = () => { const r = rows.find((x) => x.id === Number(b.dataset.ce)); formModal({ title: `Edit ${r.name}`, fields: def.fields(), values: r, onSubmit: save(r.id) }); });
  $$('[data-cd]').forEach((b) => b.onclick = guard(async () => { if (await confirmBox('Delete this entry? Linked assets keep their data but lose the link.')) { await api('DELETE', `/api/${kind}/${b.dataset.cd}`); await refreshMeta(); reload(); } }));
});

// ------------------------------------------------------------------ locations map (Leaflet + OpenStreetMap tiles)
async function loadLeaflet() {
  if (window.L) return;
  const css = document.createElement('link');
  css.rel = 'stylesheet'; css.href = 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css';
  document.head.appendChild(css);
  await new Promise((res, rej) => { const s = document.createElement('script'); s.src = 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js'; s.onload = res; s.onerror = rej; setTimeout(() => rej(new Error('Map library unavailable (offline?)')), 8000); document.head.appendChild(s); });
}
route(/^\/map$/, async (v, q) => {
  const d = await GET('/api/map');
  const placed = d.locations.filter((l) => l.lat != null);
  v.innerHTML = head('Locations map', '', '', 'Where your assets, people and stock are.') + `
    <div class="map-layout"><div class="card map-list"><div class="card-head"><h2>Sites</h2><div class="actions muted small">${placed.length}/${d.locations.length} on map</div></div>
      ${d.locations.length ? d.locations.map((l) => `<div class="site ${q.focus == l.id ? 'sel' : ''}" data-site="${l.id}"><div class="site-main"><b>${esc(l.name)}</b>
        <span class="small muted">${l.assets} assets · ${l.people} people${l.stock ? ` · ${l.stock} stock` : ''}</span></div>
        ${l.lat == null ? (can('tech') ? `<button class="btn sm" data-place="${l.id}">${icon('mapPin', 'sm')} Place</button>` : '<span class="small muted">Not placed</span>') : `<button class="icon-btn" data-fly="${l.id}" title="Show on map">${icon('mapPin', 'sm')}</button>`}</div>`).join('')
        : `<div class="empty">No locations yet. <a href="#/locations">Add locations</a> first.</div>`}
      ${d.unassigned ? `<p class="small muted" style="margin:12px 4px 0">${d.unassigned} assets have no location. <a href="#/assets">Assign them</a>.</p>` : ''}</div>
      <div class="card map-card"><div id="map"></div><div id="mapHint" class="map-hint" hidden></div></div></div>`;
  try { await loadLeaflet(); } catch (e) { $('#map').innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
  const L = window.L;
  const map = L.map('map', { zoomControl: true, attributionControl: true });
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 19, attribution: '&copy; OpenStreetMap contributors' }).addTo(map);
  const markers = {};
  const popup = (l) => `<b>${esc(l.name)}</b><br>${esc(l.address || '')}<br><span>${l.assets} assets (${l.in_use} in use, ${l.in_stock} in stock)<br>${l.people} people · ${l.stock} stock items</span><br>
    <a href="#/assets?location_id=${l.id}">View assets</a> · <a href="#/locations/${l.id}">Location</a>${can('tech') ? ` · <a href="#" data-move="${l.id}">Move pin</a>` : ''}`;
  for (const l of placed) {
    const r = Math.max(9, Math.min(30, 8 + Math.sqrt(l.assets) * 3));
    markers[l.id] = L.circleMarker([l.lat, l.lng], { radius: r, color: '#1d4ed8', weight: 2, fillColor: '#3b82f6', fillOpacity: 0.55 }).addTo(map).bindPopup(popup(l)).bindTooltip(`${l.name} · ${l.assets}`, { direction: 'top' });
  }
  if (placed.length) map.fitBounds(L.latLngBounds(placed.map((l) => [l.lat, l.lng])).pad(0.4), { maxZoom: 13 }); else map.setView([20.6, 78.9], 4);
  if (q.focus && markers[q.focus]) { map.setView(markers[q.focus].getLatLng(), 14); markers[q.focus].openPopup(); }
  let placing = null;
  const startPlacing = (id) => {
    placing = Number(id);
    const l = d.locations.find((x) => x.id === placing);
    $('#mapHint').hidden = false; $('#mapHint').innerHTML = `${icon('mapPin', 'sm')} Click the map to place <b>${esc(l.name)}</b> <button class="btn sm" id="cancelPlace">Cancel</button>`;
    $('#map').classList.add('placing');
    $('#cancelPlace').onclick = () => { placing = null; $('#mapHint').hidden = true; $('#map').classList.remove('placing'); };
  };
  map.on('click', guard(async (e) => {
    if (!placing) return;
    await api('PUT', `/api/locations/${placing}/position`, { lat: Number(e.latlng.lat.toFixed(6)), lng: Number(e.latlng.lng.toFixed(6)) });
    toast('Location placed'); const id = placing; placing = null; location.hash = `#/map?focus=${id}`; reload();
  }));
  map.on('popupopen', (e) => { const a = e.popup.getElement().querySelector('[data-move]'); if (a) a.onclick = (ev) => { ev.preventDefault(); map.closePopup(); startPlacing(a.dataset.move); }; });
  $$('[data-place]').forEach((b) => b.onclick = () => startPlacing(b.dataset.place));
  $$('[data-fly]').forEach((b) => b.onclick = () => { const m = markers[b.dataset.fly]; map.flyTo(m.getLatLng(), 14, { duration: 0.6 }); m.openPopup(); });
  setTimeout(() => map.invalidateSize(), 50);
});

// ------------------------------------------------------------------ permission groups
route(/^\/groups$/, async (v) => {
  const d = await GET('/api/groups');
  const PLAB = { view: 'View', edit: 'Create & edit', delete: 'Delete', checkout: 'Check out / in', audit: 'Audit', run: 'Run imports' };
  const editor = (g = { name: '', description: '', perms: [] }) => {
    const m = modal({
      title: g.id ? `Edit group: ${g.name}` : 'New permission group', submitLabel: 'Save group', wide: true,
      body: `<div class="form-grid"><div class="field"><label>Group name</label><input name="name" value="${esc(g.name)}" required></div>
        <div class="field"><label>Description</label><input name="description" value="${esc(g.description || '')}"></div></div>
        <div style="display:flex;gap:8px;margin:14px 0 8px"><span class="small muted" style="align-self:center">Start from:</span>
          <button type="button" class="btn sm" data-preset="viewer">Viewer defaults</button><button type="button" class="btn sm" data-preset="tech">Technician defaults</button><button type="button" class="btn sm" data-preset="none">Nothing</button></div>
        <div class="table-wrap"><table class="perm-matrix"><thead><tr><th>Area</th>${Object.values(PLAB).map((l) => `<th class="c">${l}</th>`).join('')}</tr></thead><tbody>
        ${d.catalog.filter((c) => c.module !== 'admin').map((c) => `<tr><td><b>${esc(c.label)}</b><div class="cell-sub">${c.module}</div></td>${Object.keys(PLAB).map((p) => `<td class="c">${c.perms.includes(p)
          ? `<input type="checkbox" data-perm="${c.module}.${p}" ${g.perms.includes(`${c.module}.${p}`) ? 'checked' : ''} aria-label="${esc(c.label)} ${PLAB[p]}">` : ''}</td>`).join('')}</tr>`).join('')}
        </tbody></table></div><p class="small muted">Administration (users, settings, security) is only available to the Administrator role and cannot be granted through a group.</p>`,
      onSubmit: async (form) => {
        const body = { ...formValues(form), perms: $$('[data-perm]', form).filter((c) => c.checked).map((c) => c.dataset.perm) };
        await api(g.id ? 'PUT' : 'POST', g.id ? `/api/groups/${g.id}` : '/api/groups', body); toast('Group saved'); reload();
      },
    });
    $$('[data-preset]', m).forEach((b) => b.onclick = () => {
      const set = b.dataset.preset === 'none' ? [] : d.role_defaults[b.dataset.preset];
      $$('[data-perm]', m).forEach((c) => { c.checked = set.includes(c.dataset.perm); });
    });
  };
  v.innerHTML = head('Permission groups', `<button class="btn primary" id="ng">${icon('plus', 'sm')} New group</button>`, '<a href="#/users">Users &amp; roles</a>',
    'Fine-grained rights. A user in a group gets exactly the group\'s permissions instead of their role defaults.')
    + callout('info', 'Roles: <b>Viewer</b> = read-only, <b>Technician</b> = manage inventory, <b>Administrator</b> = everything, <b>Self-service</b> = only their own assets. Assign a group on the user to customise.')
    + table([{ key: 'name', render: (g) => `<b>${esc(g.name)}</b><div class="cell-sub">${esc(g.description || '')}</div>` },
      { key: 'perms', label: 'Permissions', render: (g) => `<div class="perm-chips">${g.perms.slice(0, 8).map((p) => `<span class="pill plain">${esc(p)}</span>`).join('')}${g.perms.length > 8 ? `<span class="muted small">+${g.perms.length - 8} more</span>` : ''}</div>` },
      { key: 'members', num: true }, { key: 'x', label: '', render: (g) => `<button class="btn sm" data-eg="${g.id}">Edit</button> <button class="btn sm danger" data-dg="${g.id}">Delete</button>` }], d.groups, { empty: 'No groups yet — users get their role defaults.' });
  $('#ng').onclick = () => editor();
  $$('[data-eg]').forEach((b) => b.onclick = () => editor(d.groups.find((g) => g.id === Number(b.dataset.eg))));
  $$('[data-dg]').forEach((b) => b.onclick = guard(async () => { if (await confirmBox('Delete this group? Members fall back to their role defaults.')) { await api('DELETE', `/api/groups/${b.dataset.dg}`); reload(); } }));
});

// ------------------------------------------------------------------ self-service portal (role: user)
function renderSelfShell() {
  $('#root').innerHTML = `<div class="self">
    <header class="self-top"><div class="brand"><img src="logo-192.png" alt=""><div class="brand-txt"><b>${esc(S.me.org_name || 'Asset Portal')}</b><small>My equipment</small></div></div>
      <div class="top-actions"><a class="btn ghost" href="#/self">${icon('box', 'sm')} My assets</a><a class="btn ghost" href="#/security">${icon('shieldCheck', 'sm')} Security</a>
        <button class="icon-btn" id="themeBtn" title="Toggle dark mode">${icon('moon')}</button>
        <button class="btn" id="logout">${icon('logout', 'sm')} Sign out</button></div></header>
    ${S.me.must_change ? `<div class="banner">${icon('alert')} Please <a href="#/security">change your initial password</a>.</div>` : ''}
    <main class="content self-content" id="view"></main></div>`;
  $('#logout').onclick = guard(async () => { await api('POST', '/api/logout'); location.hash = ''; S.me = null; renderLogin(); });
  $('#themeBtn').onclick = () => {
    const cur = document.documentElement.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    document.documentElement.dataset.theme = cur === 'dark' ? 'light' : 'dark';
    try { localStorage.setItem('theme', document.documentElement.dataset.theme); } catch { /* storage unavailable */ }
  };
}
route(/^\/self$/, async (v) => {
  const d = await GET('/api/self');
  if (!d.person) { v.innerHTML = head('My assets') + callout('warn', 'Your account is not linked to an employee record yet. Please contact IT.'); return; }
  const pending = d.assets.filter((a) => a.accept_status === 'pending');
  v.innerHTML = head(`Hello, ${esc(d.person.name.split(' ')[0])}`, '', '', 'Equipment assigned to you by IT.') + `
    ${pending.map((a) => `<div class="card accept-card" style="margin-bottom:16px"><div class="card-head"><h2>${icon('tag')} Please confirm you received: ${esc(a.name)}</h2></div>
      <dl class="kv"><dt>Asset tag</dt><dd class="mono">${esc(a.asset_tag)}</dd><dt>Model</dt><dd>${esc([a.manufacturer, a.model].filter(Boolean).join(' ') || '—')}</dd>
        <dt>Serial</dt><dd class="mono">${esc(a.serial || '—')}</dd><dt>Assigned</dt><dd>${fmtDate(a.out_at)}${a.due_at ? ` · return by <b>${esc(a.due_at)}</b>` : ''}</dd></dl>
      <div class="eula">${esc(d.eula)}</div>
      <form class="accept-form" data-co="${a.checkout_id}"><div class="form-grid"><div class="field"><label>Sign by typing your full name: <b>${esc(d.person.name)}</b></label><input name="signature" autocomplete="name" required></div>
        <div class="field"><label>Comment (optional)</label><input name="note" placeholder="e.g. received with charger"></div></div>
        <div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary">${icon('check', 'sm')} Accept</button><button type="button" class="btn danger" data-decline="${a.checkout_id}">Decline</button></div></form></div>`).join('')}
    <div class="kpis"><div class="kpi"><span class="chip">${icon('monitor')}</span><div><div class="v">${d.assets.length}</div><div class="l">Assets assigned to you</div></div></div>
      <div class="kpi"><span class="chip">${icon('box')}</span><div><div class="v">${d.stock.reduce((s, x) => s + x.qty, 0)}</div><div class="l">Accessories you hold</div></div></div>
      <div class="kpi ${pending.length ? 'warn' : 'ok'}"><span class="chip">${icon('tag')}</span><div><div class="v">${pending.length}</div><div class="l">Awaiting your confirmation</div></div></div></div>
    <div class="card" style="margin-bottom:16px"><div class="card-head"><h2>My assets</h2></div>${table([
      { key: 'name', render: (a) => `<div class="cell-asset"><span class="type-ic">${icon(TYPE_ICON[a.type] || 'box', 'sm')}</span><div><b>${esc(a.name)}</b><div class="cell-sub mono">${esc(a.asset_tag)}</div></div></div>` },
      { key: 'model', render: (a) => esc([a.manufacturer, a.model].filter(Boolean).join(' ')) }, { key: 'serial', render: (a) => `<span class="mono small">${esc(a.serial || '')}</span>` },
      { key: 'due_at', label: 'Return by', render: (a) => esc(a.due_at || '—') },
      { key: 'accept_status', label: 'Status', render: (a) => (a.accept_status === 'pending' ? pill('warn', 'Awaiting confirmation') : a.accept_status === 'accepted' ? pill('ok', 'Accepted') : a.accept_status === 'declined' ? pill('crit', 'Declined') : pill('ok', 'Assigned')) },
      { key: 'warranty_end', label: 'Warranty', render: (a) => esc(a.warranty_end || '—') }], d.assets, { empty: 'Nothing is assigned to you.' })}</div>
    ${d.stock.length ? `<div class="card" style="margin-bottom:16px"><div class="card-head"><h2>Accessories</h2></div>${table([{ key: 'name', render: (s) => `<b>${esc(s.name)}</b><div class="cell-sub">${esc(s.model_number || '')}</div>` }, { key: 'qty', num: true }, { key: 'ts', label: 'Since', render: (s) => fmtDate(s.ts) }], d.stock)}</div>` : ''}
    <div class="card"><div class="card-head"><h2>History</h2></div>${table([{ key: 'name', render: (h) => `${esc(h.name)} <span class="muted small mono">${esc(h.asset_tag)}</span>` },
      { key: 'out_at', label: 'Received', render: (h) => fmtDate(h.out_at) }, { key: 'in_at', label: 'Returned', render: (h) => (h.in_at ? fmtDate(h.in_at) : '—') }], d.history, { empty: 'No history' })}</div>
    <p class="small muted" style="margin-top:16px">Something wrong or missing? Contact your IT department.</p>`;
  $$('.accept-form').forEach((f) => f.onsubmit = guard(async (e) => {
    e.preventDefault();
    await api('POST', `/api/self/checkouts/${f.dataset.co}/accept`, formValues(f)); toast('Thank you — receipt confirmed'); reload();
  }));
  $$('[data-decline]').forEach((b) => b.onclick = () => formModal({ title: 'Decline this assignment', submitLabel: 'Decline',
    fields: [{ name: 'note', label: 'Why? (sent to IT)', type: 'textarea', required: true, full: true, placeholder: 'e.g. I did not receive this device' }],
    onSubmit: async (val) => { await api('POST', `/api/self/checkouts/${b.dataset.decline}/decline`, val); toast('IT has been notified'); reload(); } }));
});

// ------------------------------------------------------------------ admin
route(/^\/settings$/, async (v) => {
  const [s, cfs] = await Promise.all([GET('/api/settings'), GET('/api/custom-fields')]);
  const sec = (t) => ({ section: t });
  const F = [
    sec('Organization'),
    { name: 'org_name', label: 'Organization name' }, { name: 'public_url', label: 'Public portal URL (used by agents)', placeholder: 'https://assets.company.local', help: 'Address computers use to reach this portal.' },
    { name: 'asset_tag_prefix', label: 'Asset tag prefix' }, { name: 'currency', label: 'Currency (ISO code)' },
    sec('Agents & alerts'),
    { name: 'agent_interval_min', label: 'Full inventory interval (minutes)', type: 'number', help: 'Minimum 5. Heartbeats are sent every minute.' },
    { name: 'offline_days', label: 'Alert when an agent is silent for (days)', type: 'number' },
    { name: 'low_disk_pct', label: 'Low disk alert below (% free)', type: 'number' }, { name: 'warranty_alert_days', label: 'Warranty alert (days before)', type: 'number' },
    { name: 'license_alert_days', label: 'License expiry alert (days before)', type: 'number' }, { name: 'contract_alert_days', label: 'Contract expiry alert (days before)', type: 'number' },
    { name: 'depreciation_years', label: 'Straight-line depreciation (years)', type: 'number' },
    sec('Assignments & audits'),
    { name: 'require_acceptance', label: 'Require users to accept assigned assets', type: 'select', blank: false, options: [{ value: '0', label: 'No' }, { value: '1', label: 'Yes — when the person has a self-service login' }] },
    { name: 'audit_interval_months', label: 'Physical audit interval (months)', type: 'number' },
    { name: 'eula_text', label: 'Acceptance text shown to users', type: 'textarea', full: true },
    sec('Security'),
    { name: 'session_idle_min', label: 'Sign out after inactivity (minutes)', type: 'number' }, { name: 'session_max_hours', label: 'Maximum session length (hours)', type: 'number' },
    { name: 'require_2fa_admins', label: 'Require two-factor for administrators', type: 'select', blank: false, options: [{ value: '0', label: 'No' }, { value: '1', label: 'Yes' }] },
  ];
  v.innerHTML = head('Settings', '', '', 'Organization-wide configuration.') + `<form class="card" id="sf" style="margin-bottom:18px"><div class="form-grid">${F.map((f) => (f.section ? `<div class="form-section">${f.section}</div>` : fieldHtml(f, s[f.name]))).join('')}</div>
    <div style="margin-top:18px"><button class="btn primary">${icon('check', 'sm')} Save settings</button></div></form>
    <div class="card"><div class="card-head"><h2>Custom asset fields</h2><div class="actions"><button class="btn" id="ncf">${icon('plus', 'sm')} Add field</button></div></div>
    ${table([{ key: 'name' }, { key: 'field_type', label: 'Type', render: (c) => titleCase(c.field_type) }, { key: 'x', label: '', render: (c) => `<button class="btn sm danger" data-dcf="${c.id}">Delete</button>` }], cfs, { empty: 'No custom fields. Add fields such as "Cost center" or "Insurance policy".' })}</div>`;
  $('#sf').onsubmit = guard(async (e) => { e.preventDefault(); await api('PUT', '/api/settings', formValues(e.target)); toast('Settings saved'); await boot(); });
  $('#ncf').onclick = () => formModal({ title: 'Add custom field', fields: [{ name: 'name', label: 'Field name', required: true }, { name: 'field_type', label: 'Type', type: 'select', blank: false, options: opts(['text', 'number', 'date']) }],
    onSubmit: async (val) => { await api('POST', '/api/custom-fields', val); await refreshMeta(); reload(); } });
  $$('[data-dcf]').forEach((b) => b.onclick = guard(async () => { await api('DELETE', `/api/custom-fields/${b.dataset.dcf}`); await refreshMeta(); reload(); }));
});
route(/^\/users$/, async (v) => {
  const [users, gd] = await Promise.all([GET('/api/users'), GET('/api/groups')]);
  const roleOpts = [{ value: 'user', label: 'Self-service — own assets only' }, { value: 'viewer', label: 'Viewer — read-only' }, { value: 'tech', label: 'Technician — manage assets' }, { value: 'admin', label: 'Administrator — full access' }];
  const extra = [{ name: 'group_id', label: 'Permission group (overrides role defaults)', type: 'select', options: opts(gd.groups) }, { name: 'person_id', label: 'Linked person (needed for self-service)', type: 'select', options: opts(S.meta.people) }];
  v.innerHTML = head('Users & roles', `<a class="btn" href="#/groups">${icon('users', 'sm')} Permission groups</a><button class="btn primary" id="nu">${icon('plus', 'sm')} Add user</button>`, '', 'Who can sign in to the portal and what they can do.') + table([
    { key: 'username', render: (u) => `<span class="avatar" style="width:26px;height:26px;font-size:11px;margin-right:8px">${esc(initials(u.name || u.username))}</span><span class="cell-main">${esc(u.username)}</span>` },
    { key: 'name' }, { key: 'email' }, { key: 'role', render: (u) => pill(u.role === 'admin' ? 'info' : '', titleCase(u.role === 'tech' ? 'technician' : u.role)) },
    { key: 'group_name', label: 'Group', render: (u) => (u.group_name ? `<a href="#/groups">${esc(u.group_name)}</a>` : '<span class="muted small">Role defaults</span>') },
    { key: 'person_name', label: 'Person', render: (u) => esc(u.person_name || '') },
    { key: 'totp_enabled', label: 'Two-factor', render: (u) => (u.totp_enabled ? pill('ok', 'Enabled') : pill('', 'Off')) },
    { key: 'last_login', label: 'Last sign-in', render: (u) => ago(u.last_login) },
    { key: 'x', label: '', render: (u) => `<button class="btn sm" data-eu="${u.id}">Edit</button> ${u.id !== S.me.id ? `<button class="btn sm danger" data-du="${u.id}">Delete</button>` : ''}` }], users);
  $('#nu').onclick = () => formModal({ title: 'Add user', values: { role: 'tech' },
    fields: [{ name: 'username', label: 'Username', required: true }, { name: 'name', label: 'Full name' }, { name: 'email', label: 'Email', type: 'email' },
      { name: 'role', label: 'Role', type: 'select', blank: false, options: roleOpts }, ...extra,
      { name: 'password', label: 'Initial password', type: 'password', required: true, full: true, help: 'At least 10 characters with letters and numbers. The user must change it at first sign-in.' }],
    onSubmit: async (val) => { await api('POST', '/api/users', val); reload(); } });
  $$('[data-eu]').forEach((b) => b.onclick = () => {
    const u = users.find((x) => x.id === Number(b.dataset.eu));
    formModal({ title: `Edit ${u.username}`, values: u, fields: [{ name: 'name', label: 'Full name' }, { name: 'email', label: 'Email', type: 'email' },
      { name: 'role', label: 'Role', type: 'select', blank: false, options: roleOpts }, ...extra, { name: 'password', label: 'Reset password (leave empty to keep)', type: 'password' },
      ...(u.totp_enabled ? [{ name: 'reset_2fa', label: 'Two-factor', type: 'select', blank: false, options: [{ value: '', label: 'Keep enabled' }, { value: '1', label: 'Reset (user lost their device)' }] }] : [])],
    onSubmit: async (val) => { if (!val.password) delete val.password; val.reset_2fa = !!val.reset_2fa; await api('PUT', `/api/users/${u.id}`, val); reload(); } });
  });
  $$('[data-du]').forEach((b) => b.onclick = guard(async () => { if (await confirmBox('Delete this user?')) { await api('DELETE', `/api/users/${b.dataset.du}`); reload(); } }));
});
route(/^\/audit$/, async (v, q) => {
  const rows = await GET(`/api/audit?${qs({ q: q.q })}`);
  v.innerHTML = head('Audit log', '', '', 'Every sign-in and change, newest first.') + `<div class="filters"><input type="search" id="aq" placeholder="Filter by user, action, entity…" value="${esc(q.q || '')}"></div>`
    + table([{ key: 'ts', label: 'When', render: (r) => fmtDT(r.ts) }, { key: 'username', label: 'User' }, { key: 'action', render: (r) => pill(/fail|locked|denied/.test(r.action) ? 'crit' : /delete|revoke|rotate/.test(r.action) ? 'warn' : '', r.action.replace(/_/g, ' ')) },
      { key: 'entity' }, { key: 'entity_id', label: 'ID' }, { key: 'detail', render: (r) => `<span class="small">${esc(r.detail || '')}</span>` }], rows);
  $('#aq').onchange = (e) => { location.hash = `#/audit?${qs({ q: e.target.value })}`; };
});

// ------------------------------------------------------------------ my security
function changePasswordModal() {
  formModal({
    title: 'Change password',
    fields: [{ name: 'current', label: 'Current password', type: 'password', required: true, full: true },
      { name: 'password', label: 'New password', type: 'password', required: true, full: true, help: 'At least 10 characters with letters and numbers.' },
      { name: 'confirm', label: 'Repeat new password', type: 'password', required: true, full: true }],
    onSubmit: async (v) => {
      if (v.password !== v.confirm) throw new Error('Passwords do not match');
      await api('PUT', '/api/me/password', { current: v.current, password: v.password });
      toast('Password changed. Other sessions were signed out.'); await boot();
    },
  });
}
async function loadQr() {
  if (window.QRCode) return;
  await new Promise((res, rej) => { const s = document.createElement('script'); s.src = 'https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js'; s.onload = res; s.onerror = rej; setTimeout(rej, 5000); document.head.appendChild(s); });
}
route(/^\/security$/, async (v) => {
  const sessions = await GET('/api/me/sessions');
  v.innerHTML = head('Security', '', '', 'Your password, two-factor authentication and active sessions.') + `<div class="grid g2">
    <div class="card"><div class="card-head"><h2>Password</h2></div>
      ${S.me.must_change ? callout('warn', 'You are still using an initial password. Change it to unlock editing.') : '<p class="muted small" style="margin-top:0">Changing your password signs out your other sessions.</p>'}
      <button class="btn primary" id="cpw">${icon('lock', 'sm')} Change password</button></div>
    <div class="card"><div class="card-head"><h2>Two-factor authentication</h2><div class="actions">${S.me.totp_enabled ? pill('ok', 'Enabled') : pill('warn', 'Not enabled')}</div></div>
      <div id="tfa">${S.me.totp_enabled
        ? `<p class="small muted" style="margin-top:0">Sign-in requires a code from your authenticator app.</p><button class="btn danger" id="tfaOff">Disable two-factor</button>`
        : `<p class="small muted" style="margin-top:0">Protect your account with a code from Microsoft Authenticator, Google Authenticator or any TOTP app.</p><button class="btn primary" id="tfaOn">${icon('shieldCheck', 'sm')} Set up two-factor</button>`}</div></div>
    <div class="card span2"><div class="card-head"><h2>Active sessions</h2><div class="actions"><button class="btn" id="revoke">Sign out all other sessions</button></div></div>
      ${table([{ key: 'user_agent', label: 'Device', render: (s) => `${esc((s.user_agent || '').replace(/^Mozilla\/5\.0 /, '').slice(0, 90))}${s.current ? ' ' + pill('ok', 'This session') : ''}` },
        { key: 'ip', label: 'IP address', render: (s) => `<span class="mono">${esc(s.ip || '')}</span>` }, { key: 'last_seen', label: 'Last active', render: (s) => ago(s.last_seen ? new Date(s.last_seen).toISOString() : null) }], sessions)}</div>
  </div>`;
  $('#cpw').onclick = changePasswordModal;
  $('#revoke').onclick = guard(async () => { await api('POST', '/api/me/sessions/revoke-others'); toast('Other sessions signed out'); reload(); });
  if ($('#tfaOff')) $('#tfaOff').onclick = () => formModal({ title: 'Disable two-factor', fields: [{ name: 'password', label: 'Confirm with your password', type: 'password', required: true, full: true }],
    onSubmit: async (val) => { await api('POST', '/api/me/2fa/disable', val); toast('Two-factor disabled'); await boot(); } });
  if ($('#tfaOn')) $('#tfaOn').onclick = guard(async () => {
    const r = await api('POST', '/api/me/2fa/setup');
    $('#tfa').innerHTML = `<ol class="steps"><li><div>Scan this QR code with your authenticator app<div id="qr" style="margin:10px 0;background:#fff;padding:8px;display:inline-block;border-radius:8px"></div>
      <div class="small muted">Can't scan? Enter this key manually:</div><div class="fingerprint" style="margin-top:4px">${esc(r.secret.match(/.{1,4}/g).join(' '))}</div></div></li>
      <li><div>Enter the 6-digit code shown in the app<form id="tfaForm" style="display:flex;gap:8px;margin-top:8px"><input id="tfaCode" class="otp" style="width:180px;height:42px!important;font-size:18px!important" inputmode="numeric" maxlength="6" autocomplete="one-time-code" required>
      <button class="btn primary">Verify &amp; enable</button></form></div></li></ol>`;
    try { await loadQr(); new window.QRCode($('#qr'), { text: r.uri, width: 168, height: 168, correctLevel: window.QRCode.CorrectLevel.M }); }
    catch { $('#qr').textContent = 'QR code unavailable offline — use the key below.'; }
    $('#tfaCode').focus();
    $('#tfaForm').onsubmit = guard(async (e) => { e.preventDefault(); await api('POST', '/api/me/2fa/enable', { code: $('#tfaCode').value }); toast('Two-factor authentication enabled'); await boot(); location.hash = '#/security'; });
  });
});

// ------------------------------------------------------------------ boot
async function refreshMeta() { S.meta = await GET('/api/meta'); }
async function boot() {
  try {
    const saved = localStorage.getItem('theme');
    if (saved) document.documentElement.dataset.theme = saved;
  } catch { /* storage unavailable */ }
  try { S.me = await api('GET', '/api/me', undefined, { noRedirect: true }); } catch { S.me = null; return renderLogin(); }
  document.title = `Asset Portal · ${S.me.org_name}`;
  if (S.me.role === 'user') {
    renderSelfShell();
    if (!/^#\/(self|security)/.test(location.hash)) location.hash = '#/self'; else navigate();
    return;
  }
  await refreshMeta();
  renderShell();
  navigate();
}
setInterval(() => { if (S.me && S.me.role !== 'user' && !document.hidden) refreshAlertBadge(); }, 60000);
document.addEventListener('click', (e) => {
  const p = e.target.closest('[data-print]');
  if (p) window.print();
  const c = e.target.closest('[data-copy]');
  if (c) navigator.clipboard?.writeText(c.dataset.copy).then(() => toast('Copied to clipboard'), () => toast('Copy failed — select the text manually', true));
});
boot();
