// Bulk import centre (Snipe-IT-style): many import types, column mapping with sample values,
// catalog auto-creation (companies, models, manufacturers, categories, suppliers), check-out on import,
// custom fields, user logins, dry runs and an automatic backup before importing.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { parseCsv } from './web.js';
import { addHistory, assetTag, nowIso } from './inventory.js';

// ---------------------------------------------------------------- field catalogue per import type
const F = (key, label, aliases = [], group = 'General') => ({ key, label, aliases, group });
const PERSON_FIELDS = [
  F('first_name', 'First name', ['first name', 'firstname', 'given name']), F('last_name', 'Last name', ['last name', 'lastname', 'surname', 'family name']),
  F('name', 'Full name', ['full name', 'name', 'display name', 'employee name']), F('email', 'Email', ['email', 'e-mail', 'mail', 'email address']),
  F('username', 'Username', ['username', 'user name', 'login', 'samaccountname', 'user id']), F('employee_number', 'Employee number', ['employee number', 'employee no', 'emp id', 'employee id', 'staff id']),
  F('title', 'Job title', ['job title', 'title', 'designation', 'position']), F('phone', 'Phone', ['phone', 'mobile', 'telephone', 'contact']),
  F('department', 'Department', ['department', 'dept', 'team']), F('location', 'Location', ['location', 'site', 'office', 'branch']),
  F('company', 'Company', ['company', 'company name', 'organization', 'organisation', 'entity']), F('notes', 'Notes', ['notes', 'comments', 'remarks']),
];
const STOCK_FIELDS = [
  F('name', 'Item name', ['name', 'item', 'item name', 'accessory name', 'consumable name', 'component name']),
  F('category', 'Category', ['category', 'group', 'type']), F('manufacturer', 'Manufacturer', ['manufacturer', 'make', 'brand']),
  F('model_number', 'Model / part number', ['model number', 'model no', 'part number', 'sku', 'model']), F('qty', 'Quantity', ['qty', 'quantity', 'count', 'stock', 'total']),
  F('min_qty', 'Minimum quantity', ['min qty', 'minimum', 'min amt', 'minimum quantity', 'reorder level']), F('unit_cost', 'Purchase cost (per unit)', ['purchase cost', 'unit cost', 'cost', 'price']),
  F('supplier', 'Supplier', ['supplier', 'vendor']), F('location', 'Location', ['location', 'site', 'store']), F('company', 'Company', ['company']),
  F('order_number', 'Order number', ['order number', 'order', 'po', 'po number', 'invoice']), F('purchase_date', 'Purchase date', ['purchase date', 'purchased', 'date']),
  F('notes', 'Notes', ['notes', 'comments']),
];
function fieldsFor(type, db) {
  if (type === 'assets') {
    return [
      F('company', 'Company', ['company', 'company name', 'organization', 'entity'], 'Asset'), F('name', 'Asset name', ['name', 'asset name', 'device name', 'computer name', 'hostname'], 'Asset'),
      F('asset_tag', 'Asset tag', ['asset tag', 'tag', 'asset id', 'asset number', 'inventory number'], 'Asset'), F('serial', 'Serial number', ['serial', 'serial number', 'serial no', 's/n', 'sn'], 'Asset'),
      F('status', 'Status', ['status', 'state', 'status label'], 'Asset'), F('type', 'Asset type', ['asset type', 'device type'], 'Asset'),
      F('location', 'Location', ['location', 'site', 'office', 'default location'], 'Asset'), F('department', 'Department', ['department', 'dept'], 'Asset'),
      F('notes', 'Asset notes', ['asset notes', 'notes', 'comments', 'remarks'], 'Asset'),
      F('hostname', 'Hostname', ['hostname', 'host name'], 'Asset'), F('ip', 'IP address', ['ip', 'ip address'], 'Asset'), F('mac', 'MAC address', ['mac', 'mac address'], 'Asset'),
      F('model', 'Model name', ['model', 'model name'], 'Model'), F('model_number', 'Model number', ['model number', 'model no', 'model no.', 'part number', 'sku'], 'Model'),
      F('manufacturer', 'Manufacturer', ['manufacturer', 'make', 'brand', 'oem'], 'Model'), F('category', 'Category', ['category', 'asset category'], 'Model'),
      F('model_notes', 'Model notes', ['model notes'], 'Model'),
      F('order_number', 'Order number', ['order number', 'order', 'po', 'po number', 'invoice', 'invoice number'], 'Purchase'), F('supplier', 'Supplier', ['supplier', 'vendor'], 'Purchase'),
      F('purchase_date', 'Purchase date', ['purchase date', 'purchased', 'date of purchase'], 'Purchase'), F('purchase_cost', 'Purchase cost', ['purchase cost', 'cost', 'price', 'amount'], 'Purchase'),
      F('warranty_months', 'Warranty (months)', ['warranty', 'warranty months'], 'Purchase'), F('warranty_end', 'Warranty end date', ['warranty end', 'warranty expires', 'warranty expiry'], 'Purchase'),
      F('eol_date', 'Asset EOL date', ['eol', 'eol date', 'asset eol date', 'end of life'], 'Purchase'), F('next_audit_date', 'Next audit date', ['next audit', 'next audit date'], 'Purchase'),
      F('checkout_type', 'Checkout type (user / location)', ['checkout type'], 'Check-out'), F('co_username', 'Checked out to: username', ['checked out to username', 'checkout username', 'assigned username'], 'Check-out'),
      F('co_first_name', 'Checked out to: first name', ['checked out to first name'], 'Check-out'), F('co_last_name', 'Checked out to: last name', ['checked out to last name'], 'Check-out'),
      F('co_email', 'Checked out to: email', ['checked out to email', 'assigned to', 'assigned email', 'owner email', 'user email', 'employee email'], 'Check-out'),
      F('co_name', 'Checked out to: full name', ['checked out to', 'assigned to name', 'owner', 'employee', 'user'], 'Check-out'),
      F('co_location', 'Checkout location', ['checkout location', 'checked out to location'], 'Check-out'),
      ...db.all('SELECT id, name FROM custom_fields ORDER BY name').map((c) => F(`cf:${c.id}`, c.name, [c.name.toLowerCase()], 'Custom fields')),
    ];
  }
  if (type === 'people') return PERSON_FIELDS.map((f) => ({ ...f, group: 'Person' }));
  if (type === 'users') {
    return [...PERSON_FIELDS.map((f) => ({ ...f, group: 'Person' })),
      F('role', 'Role (user/viewer/tech)', ['role', 'access level'], 'Login'), F('activated', 'Activated (can sign in)', ['activated', 'active', 'enabled', 'login enabled'], 'Login'),
      F('password', 'Initial password', ['password'], 'Login')];
  }
  if (['accessories', 'consumables', 'components'].includes(type)) return STOCK_FIELDS.map((f) => ({ ...f, group: 'Item' }));
  if (type === 'licenses') {
    return [F('name', 'Software / license name', ['name', 'license name', 'software', 'product'], 'License'), F('product_key', 'Product key', ['product key', 'license key', 'serial', 'key'], 'License'),
      F('seats', 'Seats', ['seats', 'quantity', 'qty', 'licenses'], 'License'), F('license_type', 'Type (per_device/per_user/site)', ['license type', 'type', 'metric'], 'License'),
      F('manufacturer', 'Manufacturer / vendor', ['manufacturer', 'vendor', 'publisher'], 'License'), F('matches', 'Matches installed software', ['matches', 'software match'], 'License'),
      F('purchase_date', 'Purchase date', ['purchase date', 'purchased'], 'Purchase'), F('expiration_date', 'Expiration date', ['expiration date', 'expiry', 'expires', 'renewal date', 'expiration'], 'Purchase'),
      F('purchase_cost', 'Purchase cost', ['purchase cost', 'cost', 'price'], 'Purchase'), F('order_number', 'Order number', ['order number', 'po', 'invoice'], 'Purchase'),
      F('company', 'Company', ['company'], 'Purchase'), F('notes', 'Notes', ['notes', 'comments', 'licensed to', 'licensed to email'], 'Purchase')];
  }
  if (type === 'locations') {
    return [F('name', 'Location name', ['name', 'location', 'location name', 'site'], 'Location'), F('address', 'Address', ['address', 'address 1', 'street'], 'Location'),
      F('address2', 'Address line 2', ['address 2', 'address2'], 'Location'), F('city', 'City', ['city', 'town'], 'Location'), F('state', 'State', ['state', 'region', 'province'], 'Location'),
      F('country', 'Country', ['country'], 'Location'), F('zip', 'Postal code', ['zip', 'postal code', 'pin code', 'pincode', 'postcode'], 'Location'),
      F('lat', 'Latitude', ['lat', 'latitude'], 'Location'), F('lng', 'Longitude', ['lng', 'lon', 'longitude'], 'Location'), F('notes', 'Notes', ['notes'], 'Location')];
  }
  throw new Error('Unknown import type');
}
export const IMPORT_TYPES = { assets: 'Assets', people: 'People', users: 'Users (with login)', accessories: 'Accessories', consumables: 'Consumables', components: 'Components', licenses: 'Licenses', locations: 'Locations' };

// ---------------------------------------------------------------- parsing helpers
const norm = (h) => String(h).replace(/[_\-.:]+/g, ' ').replace(/\s+/g, ' ').trim().toLowerCase();
const MONTHS = { jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, sept: 9, oct: 10, nov: 11, dec: 12 };
const y4 = (y) => (y < 100 ? (y < 70 ? 2000 + y : 1900 + y) : y);
const ymd = (y, m, d) => {
  const dt = new Date(Date.UTC(y4(y), m - 1, d));
  if (dt.getUTCMonth() !== m - 1 || dt.getUTCDate() !== d) return null;
  return dt.toISOString().slice(0, 10);
};
/** Accepts ISO, "11-Sep-26", "11 Sep 2026", "Sep 11, 2026", dd/mm/yyyy (or mm/dd with fmt=MDY), and Excel serial numbers. */
export function parseDate(v, fmt = 'DMY') {
  const s = String(v ?? '').trim();
  if (!s) return null;
  let m;
  if ((m = /^(\d{4})-(\d{1,2})-(\d{1,2})/.exec(s))) return ymd(+m[1], +m[2], +m[3]);
  const mon = (t) => { const l = t.toLowerCase(); return MONTHS[l.slice(0, 4)] || MONTHS[l.slice(0, 3)]; };
  if ((m = /^(\d{1,2})[\s\-/.]([A-Za-z]{3,9})[\s\-/.,]+(\d{2,4})$/.exec(s)) && mon(m[2])) return ymd(+m[3], mon(m[2]), +m[1]);   // 11-Sep-26
  if ((m = /^([A-Za-z]{3,9})[\s\-/.]+(\d{1,2}),?[\s\-/.]+(\d{2,4})$/.exec(s)) && mon(m[1])) return ymd(+m[3], mon(m[1]), +m[2]);  // Sep 11, 2026
  if ((m = /^(\d{1,2})[/.\-](\d{1,2})[/.\-](\d{2,4})$/.exec(s))) {
    const a = +m[1], b = +m[2];
    if (a > 12) return ymd(+m[3], b, a);
    if (b > 12) return ymd(+m[3], a, b);
    return fmt === 'MDY' ? ymd(+m[3], a, b) : ymd(+m[3], b, a);
  }
  if (/^\d{5}(\.\d+)?$/.test(s) && +s > 20000 && +s < 80000) return new Date(Date.UTC(1899, 11, 30) + Math.floor(+s) * 86400000).toISOString().slice(0, 10);
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString().slice(0, 10);
}
/** Numbers as people type them: "58,500", "4,50,000", "₹ 1,200.50", "1.2 lakh", "2 crore", "15k". */
function num(v, label) {
  if (v === '' || v === null || v === undefined) return null;
  let c = String(v).toLowerCase().replace(/rs\.?|inr|usd|eur|[$€£₹,\s]/g, '');
  let mult = 1;
  const unit = /(lakhs?|lacs?|crores?|cr|k)$/.exec(c);
  if (unit) { mult = /^l/.test(unit[1]) ? 1e5 : /^c/.test(unit[1]) ? 1e7 : 1e3; c = c.slice(0, -unit[1].length); }
  if (!/^-?\d+(\.\d+)?$/.test(c)) throw new Error(`${label} must be a number (got "${v}")`);
  return Math.round(Number(c) * mult * 100) / 100;
}
const STATUS_MAP = {
  stock: 'in_stock', 'in stock': 'in_stock', 'ready to deploy': 'in_stock', deployable: 'in_stock', available: 'in_stock', spare: 'in_stock', new: 'in_stock', pending: 'in_stock',
  deployed: 'in_use', 'in use': 'in_use', assigned: 'in_use', active: 'in_use', allocated: 'in_use', issued: 'in_use',
  'out for repair': 'in_repair', repair: 'in_repair', broken: 'in_repair', faulty: 'in_repair', 'under repair': 'in_repair', damaged: 'in_repair',
  reserved: 'reserved', archived: 'retired', retired: 'retired', 'end of life': 'retired', eol: 'retired', disposed: 'disposed', scrapped: 'disposed', 'e waste': 'disposed', sold: 'disposed',
  lost: 'lost', stolen: 'lost', 'lost/stolen': 'lost', missing: 'lost',
};
const TYPE_HINTS = [[/laptop|notebook|travelmate|thinkpad|latitude|elitebook|macbook|probook|vivobook|ideapad|inspiron 1|zenbook|chromebook/i, 'laptop'],
  [/server|poweredge|proliant|rack/i, 'server'], [/desktop|workstation|optiplex|thinkcentre|elitedesk|prodesk|imac|\bpc\b|cpu|tower/i, 'workstation'],
  [/monitor|display|screen|lcd|led tv/i, 'monitor'], [/printer|laserjet|mfp|scanner|plotter/i, 'printer'], [/switch|router|firewall|access point|\bap\b|wifi|fortigate|meraki|catalyst/i, 'network'],
  [/phone|iphone|mobile|galaxy|android/i, 'phone'], [/tablet|ipad|tab /i, 'tablet'], [/\bups\b|battery backup/i, 'ups'], [/\bnas\b|storage|san\b|synology/i, 'storage'],
  [/vm|virtual/i, 'virtual_machine'], [/keyboard|mouse|headset|webcam|dock|projector/i, 'peripheral']];

// ---------------------------------------------------------------- files
export function readRows(csv) { return parseCsv(String(csv || ''), { rawHeaders: true }); }

export function analyse(csv, type, db, previousMapping) {
  const rows = readRows(csv);
  if (!rows.length) throw new Error('The file has no data rows (the first row must be the column headers)');
  const headers = Object.keys(rows[0]);
  const fields = fieldsFor(type, db);
  const guess = {};
  const used = new Set();
  const take = (h, key) => { guess[h] = key; used.add(key); };
  // 1) keep the user's previous choices for this file, 2) exact label/alias, 3) alias contained in the header
  if (previousMapping) for (const [h, k] of Object.entries(previousMapping)) if (headers.includes(h) && fields.some((f) => f.key === k) && !used.has(k)) take(h, k);
  for (const h of headers) {
    if (guess[h]) continue;
    const n = norm(h);
    const f = fields.find((x) => !used.has(x.key) && (norm(x.label) === n || norm(x.key) === n || x.aliases.includes(n)));
    if (f) take(h, f.key);
  }
  for (const h of headers) {
    if (guess[h]) continue;
    const n = ` ${norm(h)} `;
    const f = fields.find((x) => !used.has(x.key) && x.aliases.some((a) => a.length >= 4 && n.includes(` ${a} `)));
    if (f) take(h, f.key);
  }
  const sample = {};
  for (const h of headers) sample[h] = (rows.find((r) => String(r[h] ?? '').trim()) || {})[h] ?? '';
  return { headers, total: rows.length, sample, rows_preview: rows.slice(0, 5), fields, guess };
}

// ---------------------------------------------------------------- run
export function runImport(db, opts, user, ctx) {
  const { csv, type, update_existing = true, dry_run = false, date_format = 'DMY', backup = false } = opts;
  fieldsFor(type, db); // validates the type
  const rows = readRows(csv);
  if (!rows.length) throw new Error('The file has no data rows');
  // "newcf" = create a custom field named after the CSV column
  const mapping = { ...(opts.mapping || {}) };
  for (const [h, k] of Object.entries(mapping)) {
    if (k === 'newcf' && type === 'assets' && !dry_run) {
      const existing = db.get('SELECT id FROM custom_fields WHERE name=? COLLATE NOCASE', h.trim());
      mapping[h] = `cf:${existing ? existing.id : db.insert('custom_fields', { name: h.trim(), field_type: 'text', applies_to: '*' })}`;
    } else if (k === 'newcf') mapping[h] = `newcf:${h.trim()}`;
  }
  const valid = new Set(fieldsFor(type, db).map((f) => f.key)); // after "newcf" columns were turned into real custom fields
  const map = Object.entries(mapping).filter(([, k]) => valid.has(k) || String(k).startsWith('newcf:'));
  if (!map.length) throw new Error('Map at least one column');

  let backupFile = null;
  if (backup && !dry_run && ctx.dataDir) {
    const dir = path.join(ctx.dataDir, 'backups');
    fs.mkdirSync(dir, { recursive: true });
    backupFile = path.join(dir, `pre-import-${new Date().toISOString().replace(/[:.]/g, '-')}.db`);
    db.exec(`VACUUM INTO '${backupFile.replace(/'/g, "''")}'`);
    const old = fs.readdirSync(dir).filter((f) => f.startsWith('pre-import-')).sort();
    for (const f of old.slice(0, Math.max(0, old.length - 10))) fs.rmSync(path.join(dir, f), { force: true });
  }

  // ---- catalog lookups (create on demand, cached per run)
  const cache = new Map();
  const named = (table, name, extra = {}) => {
    const v = String(name ?? '').trim();
    if (!v) return null;
    const ck = `${table}|${v.toLowerCase()}|${JSON.stringify(extra)}`;
    if (cache.has(ck)) return cache.get(ck);
    const where = Object.keys(extra).map((k) => ` AND ${k}=?`).join('');
    const row = db.get(`SELECT id FROM ${table} WHERE name=? COLLATE NOCASE${where}`, v, ...Object.values(extra));
    const id = row ? row.id : db.insert(table, { name: v, ...extra });
    cache.set(ck, id);
    return id;
  };
  const model = (r) => {
    const name = String(r.model || r.model_number || '').trim();
    if (!name) return null;
    const mnum = String(r.model_number || '').trim() || null;
    const row = db.get('SELECT id FROM asset_models WHERE name=? COLLATE NOCASE AND COALESCE(model_number,\'\')=COALESCE(?,\'\') COLLATE NOCASE', name, mnum);
    if (row) {
      if (r.model_notes) db.run('UPDATE asset_models SET notes=COALESCE(notes, ?) WHERE id=?', r.model_notes, row.id);
      return row.id;
    }
    return db.insert('asset_models', { name, model_number: mnum, manufacturer_id: named('manufacturers', r.manufacturer), category_id: named('categories', r.category, { kind: 'asset' }), notes: r.model_notes || null });
  };
  const personFrom = (r, prefix) => {
    const email = r[`${prefix}email`], username = r[`${prefix}username`];
    const full = (r[`${prefix}name`] || [r[`${prefix}first_name`], r[`${prefix}last_name`]].filter(Boolean).join(' ')).trim();
    const found = (email && db.get('SELECT id FROM people WHERE email=? COLLATE NOCASE', email))
      || (username && db.get('SELECT id FROM people WHERE username=? COLLATE NOCASE', username))
      || (full && db.get('SELECT id FROM people WHERE name=? COLLATE NOCASE', full));
    if (found) return found.id;
    if (!email && !username && !full) return null;
    return db.insert('people', { name: full || (email ? email.split('@')[0].replace(/[._]+/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()) : username), email: email || null, username: username || null });
  };
  const date = (v, label) => { const d = parseDate(v, date_format); if (d === undefined) throw new Error(`${label}: "${v}" is not a date I understand`); return d; };

  let created = 0, updated = 0, skipped = 0, checked_out = 0;
  const errors = [], credentials = [], createdCatalog = { before: catalogCounts(db) };
  db.exec('BEGIN');
  try {
    rows.forEach((raw, i) => {
      const r = {};
      for (const [h, k] of map) { const v = String(raw[h] ?? '').trim(); if (v !== '') r[k] = v; }
      if (!Object.keys(r).length) { skipped++; return; }
      db.exec('SAVEPOINT row');
      try {
        const out = importRow(type, r);
        if (out === 'created') created++; else if (out === 'updated') updated++; else skipped++;
        db.exec('RELEASE row');
      } catch (e) { db.exec('ROLLBACK TO row'); db.exec('RELEASE row'); errors.push({ row: i + 2, error: e.message, value: Object.values(r).slice(0, 3).join(' · ') }); }
    });
    createdCatalog.after = catalogCounts(db);
    db.exec(dry_run ? 'ROLLBACK' : 'COMMIT');
  } catch (e) { try { db.exec('ROLLBACK'); } catch { /* already rolled back */ } throw e; }

  function importRow(t, r) {
    if (t === 'assets') {
      const rec = {};
      for (const f of ['name', 'asset_tag', 'serial', 'hostname', 'ip', 'mac', 'order_number', 'notes']) if (r[f]) rec[f] = r[f];
      if (r.company) rec.company_id = named('companies', r.company);
      if (r.model || r.model_number) {
        rec.model_id = model(r);
        const m = db.get('SELECT am.name, am.model_number, mf.name AS mfr, c.name AS cat FROM asset_models am LEFT JOIN manufacturers mf ON mf.id=am.manufacturer_id LEFT JOIN categories c ON c.id=am.category_id WHERE am.id=?', rec.model_id);
        rec.model = [m.name, m.model_number && m.model_number !== m.name ? m.model_number : null].filter(Boolean).join(' ');
        if (m.mfr) rec.manufacturer = m.mfr;
      }
      if (r.manufacturer && !rec.manufacturer) { rec.manufacturer = r.manufacturer; named('manufacturers', r.manufacturer); }
      if (r.category) named('categories', r.category, { kind: 'asset' });
      if (r.supplier) { rec.supplier_id = named('suppliers', r.supplier); rec.vendor = r.supplier; }
      if (r.status) {
        const s = STATUS_MAP[norm(r.status)] || (ctx.ASSET_STATUSES.includes(norm(r.status).replace(/ /g, '_')) ? norm(r.status).replace(/ /g, '_') : null);
        if (!s) throw new Error(`Unknown status "${r.status}" (use e.g. Stock, Deployed, Broken, Archived, Lost)`);
        rec.status = s;
      }
      const typeHint = `${r.type || ''} ${r.category || ''} ${r.model || ''} ${r.model_number || ''} ${r.name || ''}`;
      if (r.type) { const t2 = norm(r.type).replace(/ /g, '_'); rec.type = ctx.ASSET_TYPES.includes(t2) ? t2 : (TYPE_HINTS.find(([re]) => re.test(typeHint))?.[1] || 'other'); }
      if (r.location) rec.location_id = named('locations', r.location);
      if (r.department) rec.department_id = named('departments', r.department);
      if (r.purchase_cost !== undefined) rec.purchase_cost = num(r.purchase_cost, 'Purchase cost');
      for (const f of ['purchase_date', 'warranty_end', 'eol_date', 'next_audit_date']) if (r[f]) rec[f] = date(r[f], f.replace(/_/g, ' '));
      if (r.warranty_months && !rec.warranty_end) {
        const months = num(r.warranty_months, 'Warranty months');
        const base = rec.purchase_date || null;
        if (base && months) { const d = new Date(`${base}T00:00:00Z`); d.setUTCMonth(d.getUTCMonth() + months); rec.warranty_end = d.toISOString().slice(0, 10); }
      }
      const custom = {};
      for (const [k, v] of Object.entries(r)) {
        if (k.startsWith('cf:')) { const cf = db.get('SELECT name FROM custom_fields WHERE id=?', Number(k.slice(3))); if (cf) custom[cf.name] = v; }
        if (k.startsWith('newcf:')) custom[k.slice(6)] = v;
      }

      let existing = rec.asset_tag ? db.get('SELECT * FROM assets WHERE asset_tag=?', rec.asset_tag) : null;
      if (!existing && rec.serial) existing = db.get('SELECT * FROM assets WHERE serial=? COLLATE NOCASE', rec.serial);
      let id, result;
      if (existing) {
        if (!update_existing) return 'skipped';
        if (Object.keys(custom).length) { let cur = {}; try { cur = JSON.parse(existing.custom_json || '{}'); } catch { /* bad json */ } rec.custom_json = JSON.stringify({ ...cur, ...custom }); }
        db.update('assets', existing.id, { ...rec, updated_at: nowIso() });
        id = existing.id; result = 'updated';
      } else {
        if (!rec.name) rec.name = rec.model || rec.serial || rec.asset_tag;
        if (!rec.name) throw new Error('Asset name (or model / serial) is required');
        if (!rec.type) rec.type = TYPE_HINTS.find(([re]) => re.test(typeHint))?.[1] || 'other';
        if (Object.keys(custom).length) rec.custom_json = JSON.stringify(custom);
        if (!rec.status) rec.status = 'in_stock';
        id = db.insert('assets', { ...rec, source: 'import' });
        if (!rec.asset_tag) db.run('UPDATE assets SET asset_tag=? WHERE id=?', assetTag(db, id), id);
        addHistory(db, id, 'created', null, null, 'Imported from CSV', user.username);
        result = 'created';
      }
      // ---- check-out on import
      const wantsLocation = norm(r.checkout_type || '') === 'location' || (r.co_location && !r.co_email && !r.co_username && !r.co_name && !r.co_first_name);
      const personId = !wantsLocation ? personFrom(r, 'co_') : null;
      const locId = wantsLocation ? named('locations', r.co_location || r.location) : null;
      if (personId || locId) {
        const open = db.get('SELECT * FROM asset_checkouts WHERE asset_id=? AND in_at IS NULL ORDER BY id DESC LIMIT 1', id);
        const same = open && ((personId && open.person_id === personId) || (locId && open.location_id === locId));
        if (!same) {
          if (open) db.run('UPDATE asset_checkouts SET in_at=?, in_by=?, in_notes=? WHERE id=?', nowIso(), user.username, 'Re-assigned by import', open.id);
          db.insert('asset_checkouts', { asset_id: id, person_id: personId, location_id: locId, out_at: nowIso(), out_by: user.username, out_notes: 'Checked out by CSV import' });
          db.update('assets', id, personId ? { person_id: personId, status: 'in_use' } : { location_id: locId, person_id: null, status: 'in_use' });
          addHistory(db, id, 'assignment', 'checked out', null, personId ? db.get('SELECT name FROM people WHERE id=?', personId).name : `Location: ${r.co_location}`, user.username);
          checked_out++;
        }
      }
      return result;
    }

    if (t === 'people' || t === 'users') {
      const name = (r.name || [r.first_name, r.last_name].filter(Boolean).join(' ')).trim()
        || (r.email ? r.email.split('@')[0].replace(/[._]+/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()) : r.username);
      if (!name) throw new Error('Name, email or username is required');
      const rec = { name };
      for (const f of ['email', 'username', 'title', 'phone', 'notes', 'employee_number']) if (r[f]) rec[f] = r[f];
      if (r.department) rec.department_id = named('departments', r.department);
      if (r.location) rec.location_id = named('locations', r.location);
      if (r.company) rec.company_id = named('companies', r.company);
      const existing = (rec.email && db.get('SELECT id FROM people WHERE email=? COLLATE NOCASE', rec.email))
        || (rec.employee_number && db.get('SELECT id FROM people WHERE employee_number=?', rec.employee_number))
        || (rec.username && db.get('SELECT id FROM people WHERE username=? COLLATE NOCASE', rec.username));
      let pid, result;
      if (existing) { if (!update_existing) return 'skipped'; db.update('people', existing.id, rec); pid = existing.id; result = 'updated'; }
      else { pid = db.insert('people', rec); result = 'created'; }
      if (t === 'users') {
        const login = (r.username || r.email || '').trim();
        const active = r.activated === undefined || /^(1|y|yes|true|active|enabled)$/i.test(r.activated);
        if (login && active && !db.get('SELECT id FROM users WHERE username=? OR person_id=?', login, pid)) {
          const role = ['user', 'viewer', 'tech'].includes(norm(r.role || 'user')) ? norm(r.role || 'user') : 'user';
          const pw = r.password && r.password.length >= 10 ? r.password : `${crypto.randomBytes(9).toString('base64url')}7a`;
          db.insert('users', { username: login, name, email: rec.email || null, role, person_id: pid, pass_hash: ctx.hashPassword(pw), must_change: 1, password_changed_at: nowIso() });
          if (!r.password) credentials.push({ username: login, name, password: pw, role });
        }
      }
      return result;
    }

    if (['accessories', 'consumables', 'components'].includes(t)) {
      const kind = { accessories: 'accessory', consumables: 'consumable', components: 'component' }[t];
      if (!r.name) throw new Error('Item name is required');
      const rec = { name: r.name, kind };
      for (const f of ['model_number', 'order_number', 'notes']) if (r[f]) rec[f] = r[f];
      if (r.category) { rec.category = r.category; named('categories', r.category, { kind }); }
      if (r.manufacturer) { rec.manufacturer = r.manufacturer; named('manufacturers', r.manufacturer); }
      if (r.supplier) { rec.supplier = r.supplier; named('suppliers', r.supplier); }
      if (r.location) rec.location_id = named('locations', r.location);
      if (r.company) rec.company_id = named('companies', r.company);
      if (r.qty !== undefined) { const q = num(r.qty, 'Quantity'); if (!Number.isInteger(q) || q < 0) throw new Error('Quantity must be a whole number ≥ 0'); rec.qty_total = q; }
      if (r.min_qty !== undefined) rec.min_qty = Math.max(0, Math.round(num(r.min_qty, 'Minimum quantity')));
      if (r.unit_cost !== undefined) rec.unit_cost = num(r.unit_cost, 'Purchase cost');
      if (r.purchase_date) rec.purchase_date = date(r.purchase_date, 'purchase date');
      const existing = db.get("SELECT * FROM stock_items WHERE kind=? AND name=? COLLATE NOCASE AND COALESCE(model_number,'')=COALESCE(?,'') COLLATE NOCASE", kind, rec.name, rec.model_number ?? null);
      if (existing) {
        if (!update_existing) return 'skipped';
        if (rec.qty_total !== undefined && rec.qty_total !== existing.qty_total) db.insert('stock_moves', { item_id: existing.id, action: 'adjust', qty: rec.qty_total - existing.qty_total, by_user: user.username, notes: 'CSV import' });
        db.update('stock_items', existing.id, rec); return 'updated';
      }
      const id = db.insert('stock_items', rec);
      if (rec.qty_total) db.insert('stock_moves', { item_id: id, action: 'restock', qty: rec.qty_total, by_user: user.username, notes: 'CSV import' });
      return 'created';
    }

    if (t === 'licenses') {
      if (!r.name) throw new Error('License name is required');
      const rec = { name: r.name, software_match: r.matches || r.name, license_type: 'per_device' };
      if (r.license_type) { const lt = norm(r.license_type).replace(/ /g, '_'); rec.license_type = ['per_device', 'per_user', 'site'].includes(lt) ? lt : /user/.test(lt) ? 'per_user' : /site|unlimited|enterprise/.test(lt) ? 'site' : 'per_device'; }
      if (r.manufacturer) { rec.vendor = r.manufacturer; named('manufacturers', r.manufacturer); }
      if (r.seats !== undefined) rec.seats = Math.round(num(r.seats, 'Seats'));
      if (r.purchase_cost !== undefined) rec.cost = num(r.purchase_cost, 'Purchase cost');
      if (r.purchase_date) rec.purchase_date = date(r.purchase_date, 'purchase date');
      if (r.expiration_date) rec.expiry_date = date(r.expiration_date, 'expiration date');
      if (r.order_number) rec.order_number = r.order_number;
      if (r.notes) rec.notes = r.notes;
      if (r.company) rec.company_id = named('companies', r.company);
      if (r.product_key) rec.license_key = ctx.encrypt(r.product_key);
      const existing = db.all('SELECT id, license_key FROM licenses WHERE name=? COLLATE NOCASE', rec.name)
        .find((l) => !r.product_key || ctx.decrypt(l.license_key) === r.product_key);
      if (existing) { if (!update_existing) return 'skipped'; db.update('licenses', existing.id, rec); return 'updated'; }
      db.insert('licenses', rec); return 'created';
    }

    if (t === 'locations') {
      if (!r.name) throw new Error('Location name is required');
      const address = [r.address, r.address2, r.city, r.state, r.zip, r.country].filter(Boolean).join(', ') || null;
      const rec = { name: r.name };
      if (address) rec.address = address;
      if (r.notes) rec.notes = r.notes;
      if (r.lat !== undefined || r.lng !== undefined) {
        const lat = num(r.lat, 'Latitude'), lng = num(r.lng, 'Longitude');
        if (lat !== null && !(lat >= -90 && lat <= 90)) throw new Error('Latitude must be between -90 and 90');
        if (lng !== null && !(lng >= -180 && lng <= 180)) throw new Error('Longitude must be between -180 and 180');
        rec.lat = lat; rec.lng = lng;
      }
      const existing = db.get('SELECT id FROM locations WHERE name=? COLLATE NOCASE', rec.name);
      if (existing) { if (!update_existing) return 'skipped'; db.update('locations', existing.id, rec); return 'updated'; }
      db.insert('locations', rec); return 'created';
    }
    throw new Error('Unknown import type');
  }

  const catalog = {};
  for (const k of Object.keys(createdCatalog.before)) { const d = createdCatalog.after[k] - createdCatalog.before[k]; if (d > 0) catalog[k] = d; }
  return { created, updated, skipped, checked_out, catalog, errors: errors.slice(0, 1000), error_count: errors.length, total: rows.length, dry_run: !!dry_run,
    credentials: dry_run ? [] : credentials, backup: backupFile ? path.basename(backupFile) : null };
}

function catalogCounts(db) {
  const c = (t) => db.get(`SELECT COUNT(*) AS n FROM ${t}`).n;
  return { companies: c('companies'), models: c('asset_models'), manufacturers: c('manufacturers'), categories: c('categories'), suppliers: c('suppliers'), locations: c('locations'), departments: c('departments'), people: c('people'), custom_fields: c('custom_fields') };
}

// Backwards-compatible helpers used by the older inline endpoints
export const importTypes = () => Object.fromEntries(Object.keys(IMPORT_TYPES).map((k) => [k, []]));
export function preview(csv, type, db) { return analyse(csv, type, db); }
