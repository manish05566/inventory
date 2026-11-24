import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { Router, HttpError, bad, notFound, toCsv, parseCsv, send, serveFile } from './web.js';
import {
  enroll, checkin, evaluateAlerts, licenseUsage, licenseStatus, addHistory, assetTag, nowIso, today, sha256,
} from './inventory.js';
import { Crypto, totpVerify, newTotpSecret } from './crypto.js';
import { auditAppend, auditVerify, createToken, createBackup, parseAllowlist, ipAllowed } from './security.js';
import { sendWebhook } from './notify.js';
import { PERM_CATALOG, ALL_PERMS, roleDefaults, effectivePerms } from './perms.js';
import { IMPORT_TYPES, analyse, runImport, readRows } from './importer.js';

export function passwordProblem(pw, username) {
  pw = String(pw || '');
  if (pw.length < 10) return 'Password must be at least 10 characters';
  if (!/[A-Za-z]/.test(pw) || !/\d/.test(pw)) return 'Password must contain letters and numbers';
  if (username && pw.toLowerCase().includes(String(username).toLowerCase())) return 'Password must not contain the username';
  return null;
}

// Brute-force protection: 5 failures per username/IP within 15 minutes locks that pair for 15 minutes.
const failures = new Map();
const LOCK_MS = 15 * 60000;
function failKey(u, ip) { return `${String(u).toLowerCase()}|${ip}`; }
function isLocked(u, ip) {
  const f = failures.get(failKey(u, ip));
  return f && f.count >= 5 && Date.now() - f.last < LOCK_MS;
}
function noteFailure(u, ip) {
  const k = failKey(u, ip);
  const f = failures.get(k);
  if (!f || Date.now() - f.last > LOCK_MS) failures.set(k, { count: 1, last: Date.now() });
  else { f.count++; f.last = Date.now(); }
}

export const ASSET_TYPES = ['workstation', 'laptop', 'server', 'virtual_machine', 'monitor', 'printer', 'network', 'storage',
  'phone', 'tablet', 'peripheral', 'ups', 'other'];
export const ASSET_STATUSES = ['in_use', 'in_stock', 'in_repair', 'reserved', 'retired', 'disposed', 'lost'];
const ROLES = { user: 0, viewer: 1, tech: 2, admin: 3 };
const ONLINE_MS = 3 * 60 * 1000;

const ASSET_EDITABLE = ['asset_tag', 'name', 'type', 'status', 'manufacturer', 'model', 'serial', 'hostname', 'domain',
  'os_name', 'os_version', 'cpu', 'cpu_cores', 'ram_mb', 'ip', 'mac', 'location_id', 'department_id', 'person_id',
  'purchase_date', 'purchase_cost', 'vendor', 'order_number', 'warranty_end', 'eol_date', 'notes', 'custom_json', 'company_id', 'model_id', 'supplier_id'];
const NUMERIC = new Set(['cpu_cores', 'ram_mb', 'purchase_cost', 'location_id', 'department_id', 'person_id', 'seats', 'cost', 'company_id', 'model_id', 'supplier_id', 'manufacturer_id', 'category_id', 'eol_months']);

// ---------- password helpers ----------
export function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return `scrypt$${salt}$${crypto.scryptSync(pw, salt, 64).toString('hex')}`;
}
function verifyPassword(pw, stored) {
  const [, salt, hash] = String(stored).split('$');
  if (!salt || !hash) return false;
  const a = Buffer.from(hash, 'hex'), b = crypto.scryptSync(pw, salt, 64);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function pick(body, fields) {
  const out = {};
  for (const f of fields) {
    if (!(f in body)) continue;
    let v = body[f];
    if (v === '' || v === undefined) v = null;
    if (v !== null && NUMERIC.has(f)) { v = Number(v); if (Number.isNaN(v)) throw bad(`${f} must be a number`); }
    if (v !== null && typeof v === 'object') v = JSON.stringify(v);
    out[f] = v;
  }
  return out;
}

export function buildApi({ db, vault, monitoring, discovery, downloadDir, dataDir, scheduleAlerts }) {
  const router = new Router();
  const r = (method, p, role, fn) => router.add(method, p, { role }, fn);
  const audit = (user, action, entity, id, detail) => auditAppend(db, {
    username: user?.username || 'system', action, entity, entity_id: id === undefined || id === null ? null : String(id), detail, ip: user?._ip,
  });
  const mustGet = (table, id) => {
    const row = db.get(`SELECT * FROM ${table} WHERE id=?`, id);
    if (!row) throw notFound(`${table.replace(/s$/, '')} not found`);
    return row;
  };
  const isOnline = (hb) => !!hb && Date.now() - Date.parse(hb) < ONLINE_MS;

  // ======================= AUTH =======================
  r('POST', '/api/login', 'public', ({ req, body, res, secure, ip }) => {
    const username = String(body.username || '').slice(0, 100);
    if (isLocked(username, ip)) {
      audit({ username }, 'login_locked', 'user', null, ip);
      throw new HttpError(429, 'Too many failed attempts. Try again in 15 minutes.');
    }
    const u = db.get('SELECT * FROM users WHERE username=?', username);
    if (!u || !verifyPassword(String(body.password || ''), u.pass_hash)) {
      noteFailure(username, ip);
      audit({ username: username || '?' }, 'login_failed', 'user', null, ip);
      throw new HttpError(401, 'Invalid username or password');
    }
    if (u.totp_enabled) {
      if (!body.otp) return { otp_required: true };
      const step = totpVerify(vault.decrypt(u.totp_secret_enc), body.otp, u.totp_last_step);
      if (!step) {
        noteFailure(username, ip);
        audit(u, 'login_failed_2fa', 'user', u.id, ip);
        throw new HttpError(401, 'Invalid authentication code');
      }
      db.run('UPDATE users SET totp_last_step=? WHERE id=?', step, u.id);
    }
    failures.delete(failKey(username, ip));
    const token = crypto.randomBytes(32).toString('hex');
    const maxH = Number(db.setting('session_max_hours', 12)) || 12;
    db.run('DELETE FROM sessions WHERE expires_at < ?', Date.now());
    db.run('INSERT INTO sessions(token,user_id,expires_at,last_seen,ip,user_agent) VALUES(?,?,?,?,?,?)',
      sha256(token), u.id, Date.now() + maxH * 3600000, Date.now(), ip, String(req.headers['user-agent'] || '').slice(0, 200));
    db.run('UPDATE users SET last_login=? WHERE id=?', nowIso(), u.id);
    audit(u, 'login', 'user', u.id, ip);
    res.setHeader('Set-Cookie', `sid=${token}; HttpOnly; Path=/; SameSite=Strict; Max-Age=${maxH * 3600}${secure ? '; Secure' : ''}`);
    return { ok: true };
  });
  r('POST', '/api/logout', 'viewer', ({ res, sid }) => {
    if (sid) db.run('DELETE FROM sessions WHERE token=?', sha256(sid));
    res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; Max-Age=0');
    return { ok: true };
  });
  r('GET', '/api/me', 'viewer', ({ user }) => ({
    id: user.id, username: user.username, name: user.name, role: user.role, must_change: !!user.must_change,
    totp_enabled: !!user.totp_enabled, perms: user._perms || effectivePerms(db, user), person_id: user.person_id || null, group_id: user.group_id || null,
    must_enable_2fa: user.role === 'admin' && db.setting('require_2fa_admins') === '1' && !user.totp_enabled,
    org_name: db.setting('org_name'), currency: db.setting('currency', 'USD'),
  }));
  r('PUT', '/api/me/password', 'viewer', ({ user, body, sid }) => {
    const u = mustGet('users', user.id);
    if (!verifyPassword(String(body.current || ''), u.pass_hash)) throw bad('Current password is incorrect');
    const problem = passwordProblem(body.password, u.username);
    if (problem) throw bad(problem);
    if (verifyPassword(String(body.password), u.pass_hash)) throw bad('New password must differ from the current one');
    db.run('UPDATE users SET pass_hash=?, must_change=0, password_changed_at=? WHERE id=?', hashPassword(body.password), nowIso(), u.id);
    db.run('DELETE FROM sessions WHERE user_id=? AND token<>?', u.id, sha256(sid || ''));
    audit(user, 'password_change', 'user', u.id);
    return { ok: true };
  });
  r('POST', '/api/me/2fa/setup', 'viewer', ({ user }) => {
    const secret = newTotpSecret();
    db.run('UPDATE users SET totp_pending_enc=? WHERE id=?', vault.encrypt(secret), user.id);
    const issuer = encodeURIComponent(db.setting('org_name') || 'Asset Portal');
    return { secret, uri: `otpauth://totp/${issuer}:${encodeURIComponent(user.username)}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30` };
  });
  r('POST', '/api/me/2fa/enable', 'viewer', ({ user, body }) => {
    const u = mustGet('users', user.id);
    const secret = vault.decrypt(u.totp_pending_enc);
    if (!secret) throw bad('Start the setup first');
    const step = totpVerify(secret, body.code);
    if (!step) throw bad('That code is not valid — check the time on your phone and try again');
    db.run('UPDATE users SET totp_secret_enc=?, totp_pending_enc=NULL, totp_enabled=1, totp_last_step=? WHERE id=?', vault.encrypt(secret), step, u.id);
    audit(user, '2fa_enabled', 'user', u.id);
    return { ok: true };
  });
  r('POST', '/api/me/2fa/disable', 'viewer', ({ user, body }) => {
    const u = mustGet('users', user.id);
    if (!verifyPassword(String(body.password || ''), u.pass_hash)) throw bad('Password is incorrect');
    db.run('UPDATE users SET totp_secret_enc=NULL, totp_enabled=0 WHERE id=?', u.id);
    audit(user, '2fa_disabled', 'user', u.id);
    return { ok: true };
  });
  r('GET', '/api/me/sessions', 'viewer', ({ user, sid }) => db.all('SELECT token, ip, user_agent, last_seen, expires_at FROM sessions WHERE user_id=? ORDER BY last_seen DESC', user.id)
    .map((s) => ({ id: s.token.slice(0, 12), ip: s.ip, user_agent: s.user_agent, last_seen: s.last_seen, current: s.token === sha256(sid || '') })));
  r('POST', '/api/me/sessions/revoke-others', 'viewer', ({ user, sid }) => {
    db.run('DELETE FROM sessions WHERE user_id=? AND token<>?', user.id, sha256(sid || ''));
    audit(user, 'sessions_revoked', 'user', user.id);
    return { ok: true };
  });

  r('GET', '/api/meta', 'viewer', () => ({
    types: ASSET_TYPES, statuses: ASSET_STATUSES,
    locations: db.all('SELECT id,name FROM locations ORDER BY name'),
    departments: db.all('SELECT id,name FROM departments ORDER BY name'),
    people: db.all('SELECT id,name,email FROM people ORDER BY name'),
    custom_fields: db.all('SELECT * FROM custom_fields ORDER BY id'),
    companies: db.all('SELECT id,name FROM companies ORDER BY name'),
    suppliers: db.all('SELECT id,name FROM suppliers ORDER BY name'),
    manufacturers: db.all('SELECT id,name FROM manufacturers ORDER BY name'),
    categories: db.all('SELECT id,name,kind FROM categories ORDER BY kind,name'),
    models: db.all(`SELECT am.id, am.name, am.model_number, am.asset_type, mf.name AS manufacturer FROM asset_models am LEFT JOIN manufacturers mf ON mf.id=am.manufacturer_id ORDER BY mf.name, am.name`),
  }));

  // ======================= AGENT (end-to-end encrypted, protocol v2) =======================
  // Enrollment: agent does ECDH with the server's pinned X25519 identity key -> AES-256-GCM.
  // Afterwards every message is AES-256-GCM under a per-agent secret, bound to agent id, message type and
  // timestamp (AAD), with a 5-minute freshness window and nonce replay cache.
  const SETUP_EXE = 'AssetAgentSetup.exe';
  const agentUpdateInfo = (() => {
    let cache = { mtime: 0 };
    return () => {
      const exe = path.join(downloadDir, SETUP_EXE);
      let st;
      try { st = fs.statSync(exe); } catch { return null; }
      if (st.mtimeMs !== cache.mtime) {
        let version = null;
        try { version = fs.readFileSync(path.join(downloadDir, 'agent-version.txt'), 'utf8').trim(); } catch { /* none */ }
        cache = { mtime: st.mtimeMs, size: st.size, version, sha256: crypto.createHash('sha256').update(fs.readFileSync(exe)).digest('hex') };
      }
      return cache.version ? { version: cache.version, sha256: cache.sha256, size: cache.size, url: `/download/${SETUP_EXE}` } : null;
    };
  })();
  // Uninstall protection: the agent only learns a salted hash of the code, bound to its own id.
  const uninstallPolicy = (agent) => {
    if (db.setting('uninstall_protection') !== '1') return { required: false };
    const code = vault.decrypt(db.setting('uninstall_code_enc', ''));
    return code ? { required: true, hash: sha256(`${agent.id}:${code}`) } : { required: false };
  };
  r('GET', '/api/agent/v2/hello', 'public', () => ({
    protocol: 2, server_pub: vault.serverPub.toString('base64'), fingerprint: vault.fingerprint,
  }));
  r('POST', '/api/agent/v2/enroll', 'public', ({ body, ip }) => {
    let key, msg;
    try {
      key = vault.enrollKey(body.epk);
      msg = Crypto.open(key, body.n, body.ct, 'enroll');
      vault.checkFresh(msg.ts, `e:${body.n}`);
    } catch (e) { throw new HttpError(400, `Enrollment rejected: ${e.message.includes('stale') ? e.message : 'could not decrypt (wrong server key?)'}`); }
    const out = enroll(db, vault, msg, ip);
    if (!out) {
      audit({ username: 'agent' }, 'enroll_denied', 'agent', null, `${msg.system?.hostname || ''} from ${ip}`);
      throw new HttpError(403, 'Invalid enrollment key');
    }
    audit({ username: 'agent' }, 'enroll', 'asset', out.asset_id, `${msg.system?.hostname || ''} from ${ip}`);
    return Crypto.seal(key, out, 'enroll-resp');
  });
  r('POST', '/api/agent/v2/msg', 'public', ({ body, ip }) => {
    const id = String(body.id || '');
    const agent = /^[0-9a-f-]{36}$/i.test(id) ? db.get('SELECT * FROM agents WHERE id=?', id) : null;
    if (!agent || !agent.secret_enc) throw new HttpError(401, 'Unknown agent');
    const key = Crypto.messageKey(Buffer.from(vault.decrypt(agent.secret_enc), 'base64'), agent.id);
    const type = String(body.t || '');
    const aad = `${agent.id}|${type}|${body.ts}`;
    let msg;
    try { msg = Crypto.open(key, body.n, body.ct, aad); vault.checkFresh(body.ts, `m:${body.n}`); }
    catch (e) { throw new HttpError(401, `Message rejected: ${e.message.includes('stale') || e.message.includes('replay') ? e.message : 'authentication failed'}`); }
    let out;
    if (type === 'heartbeat') {
      db.run('UPDATE agents SET last_heartbeat=?, last_ip=?, version=COALESCE(?,version) WHERE id=?', nowIso(), ip, msg.agent_version || null, agent.id);
      db.run('UPDATE assets SET last_seen=? WHERE id=?', nowIso(), agent.asset_id);
      out = { interval_min: Number(db.setting('agent_interval_min', 60)), scan_now: agent.scan_requested === 1, update: agentUpdateInfo(), monitoring: monitoring.policy(), uninstall: uninstallPolicy(agent) };
    } else if (type === 'checkin') {
      if (!checkin(db, agent, msg, ip)) throw new HttpError(401, 'Asset removed');
      scheduleAlerts();
      out = { ok: true, interval_min: Number(db.setting('agent_interval_min', 60)), update: agentUpdateInfo(), monitoring: monitoring.policy(), uninstall: uninstallPolicy(agent) };
    } else if (type === 'policy') {
      const shotNow = agent.scan_requested >= 2;
      if (shotNow) db.run('UPDATE agents SET scan_requested=0 WHERE id=?', agent.id);
      out = { monitoring: monitoring.policy(), shot_now: shotNow };
    } else if (type === 'activity') {
      monitoring.ingestActivity(agent, msg);
      out = { ok: true, monitoring: monitoring.policy() };
    } else if (type === 'location') {
      monitoring.ingestLocation(agent, msg);
      out = { ok: true };
    } else if (type === 'screenshot') {
      out = monitoring.saveScreenshot(agent, msg);
    } else throw bad('Unknown message type');
    return Crypto.seal(key, out, `${aad}|resp`);
  });
  r('GET', '/api/agents', 'viewer', () => db.all(`SELECT g.id, g.asset_id, g.version, g.enrolled_at, g.last_checkin, g.last_heartbeat,
      g.last_ip, g.scan_requested, a.name, a.asset_tag, a.os_name, a.last_user FROM agents g JOIN assets a ON a.id=g.asset_id ORDER BY a.name`)
    .map((g) => ({ ...g, online: isOnline(g.last_heartbeat) })));
  r('DELETE', '/api/agents/:id', 'tech', ({ params, user }) => {
    db.run('DELETE FROM agents WHERE id=?', params.id);
    audit(user, 'delete', 'agent', params.id);
    return { ok: true };
  });
  r('GET', '/api/agent-info', 'viewer', ({ user, origin }) => ({
    package: agentUpdateInfo(),
    exe_available: fs.existsSync(path.join(downloadDir, SETUP_EXE)),
    fingerprint: vault.fingerprint,
    server_url: db.setting('public_url') || origin,
    enrollment_key: ROLES[user.role] >= ROLES.tech ? db.setting('enrollment_key') : null,
    interval_min: Number(db.setting('agent_interval_min', 60)),
  }));

  // ======================= ASSETS =======================
  const ASSET_SORT = { name: 'a.name', asset_tag: 'a.asset_tag', type: 'a.type', status: 'a.status', os: 'a.os_name', ip: 'a.ip',
    last_seen: 'a.last_seen', location: 'l.name', person: 'p.name', model: 'a.model', warranty_end: 'a.warranty_end', created_at: 'a.created_at' };
  const assetQuery = (q) => {
    const where = [], p = [];
    if (q.q) {
      const like = `%${q.q}%`;
      where.push(`(a.name LIKE ? OR a.asset_tag LIKE ? OR a.serial LIKE ? OR a.hostname LIKE ? OR a.ip LIKE ? OR a.mac LIKE ?
        OR a.last_user LIKE ? OR a.model LIKE ? OR a.manufacturer LIKE ? OR p.name LIKE ?)`);
      p.push(like, like, like, like, like, like, like, like, like, like);
    }
    if (q.category_id) { where.push('am.category_id=?'); p.push(q.category_id); }
    for (const f of ['type', 'status', 'source', 'location_id', 'department_id', 'person_id', 'company_id', 'model_id', 'supplier_id']) {
      if (q[f]) { where.push(`a.${f}=?`); p.push(q[f]); }
    }
    if (q.os) { where.push('a.os_name LIKE ?'); p.push(`%${q.os}%`); }
    if (q.software_id) { where.push('a.id IN (SELECT asset_id FROM asset_software WHERE software_id=?)'); p.push(q.software_id); }
    if (q.agent === 'online') { where.push('g.last_heartbeat >= ?'); p.push(new Date(Date.now() - ONLINE_MS).toISOString()); }
    if (q.agent === 'offline') { where.push('g.id IS NOT NULL AND (g.last_heartbeat IS NULL OR g.last_heartbeat < ?)'); p.push(new Date(Date.now() - ONLINE_MS).toISOString()); }
    if (q.agent === 'none') where.push('g.id IS NULL');
    if (q.ids) { const ids = String(q.ids).split(',').map(Number).filter(Boolean); where.push(`a.id IN (${ids.map(() => '?').join(',') || 'NULL'})`); p.push(...ids); }
    const from = `FROM assets a LEFT JOIN locations l ON l.id=a.location_id LEFT JOIN departments d ON d.id=a.department_id
      LEFT JOIN people p ON p.id=a.person_id LEFT JOIN agents g ON g.asset_id=a.id LEFT JOIN companies co ON co.id=a.company_id
      LEFT JOIN asset_models am ON am.id=a.model_id LEFT JOIN categories cat ON cat.id=am.category_id ${where.length ? 'WHERE ' + where.join(' AND ') : ''}`;
    const sort = ASSET_SORT[q.sort] || 'a.name';
    const dir = q.dir === 'desc' ? 'DESC' : 'ASC';
    return { from, p, order: `ORDER BY ${sort} ${dir} NULLS LAST, a.id` };
  };
  const ASSET_COLS = `a.id,a.asset_tag,a.name,a.type,a.status,a.source,a.manufacturer,a.model,a.serial,a.hostname,a.os_name,a.os_version,
    a.cpu,a.ram_mb,a.disk_total_gb,a.disk_free_gb,a.ip,a.mac,a.last_user,a.last_seen,a.warranty_end,a.purchase_date,a.purchase_cost,a.vendor,
    a.location_id,a.department_id,a.person_id,l.name AS location,d.name AS department,p.name AS person,
    g.id AS agent_id,g.last_heartbeat,g.version AS agent_version,a.company_id,a.model_id,a.order_number,co.name AS company,am.model_number,cat.name AS category,a.next_audit_date`;

  r('GET', '/api/assets', 'viewer', ({ query }) => {
    const { from, p, order } = assetQuery(query);
    const limit = Math.min(Number(query.limit) || 50, 1000), page = Math.max(Number(query.page) || 1, 1);
    const total = db.get(`SELECT COUNT(*) AS n ${from}`, ...p).n;
    const rows = db.all(`SELECT ${ASSET_COLS} ${from} ${order} LIMIT ? OFFSET ?`, ...p, limit, (page - 1) * limit)
      .map((a) => ({ ...a, online: isOnline(a.last_heartbeat) }));
    return { total, page, limit, rows };
  });

  const EXPORT_COLS = ['asset_tag', 'name', 'type', 'status', 'source', 'manufacturer', 'model', 'serial', 'hostname', 'os_name', 'os_version',
    'cpu', 'ram_mb', 'disk_total_gb', 'disk_free_gb', 'ip', 'mac', 'last_user', 'location', 'department', 'person', 'purchase_date',
    'purchase_cost', 'vendor', 'warranty_end', 'last_seen'].map((k) => ({ key: k }));
  r('GET', '/api/assets/export', 'viewer', ({ query, res }) => {
    const { from, p, order } = assetQuery(query);
    const rows = db.all(`SELECT ${ASSET_COLS} ${from} ${order}`, ...p);
    send(res, 200, toCsv(EXPORT_COLS, rows), { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': `attachment; filename="assets-${today()}.csv"` });
  });

  r('POST', '/api/assets/import', 'tech', ({ body, user }) => {
    const rows = parseCsv(typeof body === 'string' ? body : String(body.csv || ''));
    if (!rows.length) throw bad('CSV is empty or has no data rows');
    const lookup = (table, name) => {
      if (!name) return null;
      const r0 = db.get(`SELECT id FROM ${table} WHERE name=? COLLATE NOCASE`, name);
      return r0 ? r0.id : db.insert(table, { name });
    };
    const person = (v) => {
      if (!v) return null;
      const r0 = db.get('SELECT id FROM people WHERE email=? COLLATE NOCASE OR name=? COLLATE NOCASE', v, v);
      return r0 ? r0.id : db.insert('people', v.includes('@') ? { name: v.split('@')[0], email: v } : { name: v });
    };
    let created = 0, updated = 0;
    const errors = [];
    db.tx(() => rows.forEach((row, i) => {
      try {
        const rec = pick(row, ASSET_EDITABLE.filter((f) => !['location_id', 'department_id', 'person_id', 'custom_json'].includes(f)));
        if ('location' in row) rec.location_id = lookup('locations', row.location);
        if ('department' in row) rec.department_id = lookup('departments', row.department);
        const who = row.assigned_to ?? row.person;
        if (who !== undefined) rec.person_id = person(who);
        if (!rec.type) delete rec.type;
        if (!rec.status) delete rec.status;
        if (rec.type && !ASSET_TYPES.includes(rec.type)) rec.type = 'other';
        if (rec.status && !ASSET_STATUSES.includes(rec.status)) throw new Error(`invalid status "${rec.status}"`);
        let existing = rec.asset_tag ? db.get('SELECT id FROM assets WHERE asset_tag=?', rec.asset_tag) : null;
        if (!existing && rec.serial) existing = db.get('SELECT id FROM assets WHERE serial=?', rec.serial);
        if (existing) { db.update('assets', existing.id, { ...rec, updated_at: nowIso() }); updated++; }
        else {
          if (!rec.name) throw new Error('name is required');
          const id = db.insert('assets', { ...rec, source: 'import' });
          if (!rec.asset_tag) db.run('UPDATE assets SET asset_tag=? WHERE id=?', assetTag(db, id), id);
          addHistory(db, id, 'created', null, null, 'Imported from CSV', user.username);
          created++;
        }
      } catch (e) { errors.push(`Row ${i + 2}: ${e.message}`); }
    }));
    audit(user, 'import', 'asset', null, `${created} created, ${updated} updated`);
    return { created, updated, errors };
  });

  r('POST', '/api/assets/bulk', 'tech', ({ body, user }) => {
    const ids = (body.ids || []).map(Number).filter(Boolean);
    if (!ids.length) throw bad('No assets selected');
    if (body.action === 'delete') {
      if (!hasPerm(user, 'assets.delete')) throw new HttpError(403, 'You do not have permission to delete assets');
      db.tx(() => ids.forEach((id) => db.run('DELETE FROM assets WHERE id=?', id)));
      audit(user, 'bulk_delete', 'asset', ids.join(','));
      return { ok: true, count: ids.length };
    }
    if (body.action === 'scan') {
      db.tx(() => ids.forEach((id) => db.run('UPDATE agents SET scan_requested=1 WHERE asset_id=?', id)));
      return { ok: true };
    }
    const changes = pick(body.changes || {}, ['status', 'location_id', 'department_id', 'person_id', 'type']);
    if (!Object.keys(changes).length) throw bad('Nothing to change');
    db.tx(() => ids.forEach((id) => updateAsset(id, changes, user)));
    audit(user, 'bulk_update', 'asset', ids.join(','), JSON.stringify(changes));
    return { ok: true, count: ids.length };
  });

  r('POST', '/api/assets', 'tech', ({ body, user }) => {
    const rec = pick(body, ASSET_EDITABLE);
    if (rec.model_id) {
      const m = db.get('SELECT am.name, am.model_number, am.asset_type, mf.name AS mfr FROM asset_models am LEFT JOIN manufacturers mf ON mf.id=am.manufacturer_id WHERE am.id=?', rec.model_id);
      if (!m) throw bad('Unknown model');
      rec.model = [m.name, m.model_number && m.model_number !== m.name ? m.model_number : null].filter(Boolean).join(' ');
      if (m.mfr) rec.manufacturer = m.mfr;
      if (m.asset_type && !rec.type) rec.type = m.asset_type;
    }
    if (rec.supplier_id) rec.vendor = db.get('SELECT name FROM suppliers WHERE id=?', rec.supplier_id)?.name ?? rec.vendor;
    if (!rec.name) throw bad('Name is required');
    if (rec.type && !ASSET_TYPES.includes(rec.type)) throw bad('Invalid type');
    if (rec.status && !ASSET_STATUSES.includes(rec.status)) throw bad('Invalid status');
    const id = db.tx(() => {
      const nid = db.insert('assets', { ...rec, source: 'manual' });
      if (!rec.asset_tag) db.run('UPDATE assets SET asset_tag=? WHERE id=?', assetTag(db, nid), nid);
      addHistory(db, nid, 'created', null, null, 'Created manually', user.username);
      return nid;
    });
    audit(user, 'create', 'asset', id, rec.name);
    return { id };
  });

  r('GET', '/api/assets/:id', 'viewer', ({ params }) => {
    const a = db.get(`SELECT a.*, l.name AS location, d.name AS department, p.name AS person, p.email AS person_email, co.name AS company, am.name AS model_name, am.model_number, cat.name AS category, su.name AS supplier
      FROM assets a LEFT JOIN locations l ON l.id=a.location_id LEFT JOIN departments d ON d.id=a.department_id
      LEFT JOIN people p ON p.id=a.person_id LEFT JOIN companies co ON co.id=a.company_id LEFT JOIN asset_models am ON am.id=a.model_id
      LEFT JOIN categories cat ON cat.id=am.category_id LEFT JOIN suppliers su ON su.id=a.supplier_id WHERE a.id=?`, params.id);
    if (!a) throw notFound('Asset not found');
    const agent = db.get('SELECT id, version, enrolled_at, last_checkin, last_heartbeat, last_ip, scan_requested FROM agents WHERE asset_id=?', a.id);
    return {
      ...a,
      hardware: a.hardware_json ? JSON.parse(a.hardware_json) : null, hardware_json: undefined,
      custom: a.custom_json ? JSON.parse(a.custom_json) : {},
      agent: agent ? { ...agent, online: isOnline(agent.last_heartbeat) } : null,
      disks: db.all('SELECT * FROM asset_disks WHERE asset_id=? ORDER BY name', a.id),
      nics: db.all('SELECT * FROM asset_nics WHERE asset_id=? ORDER BY name', a.id),
      software: db.all(`SELECT s.id, s.name, s.publisher, s.status, s.category, x.version, x.install_date FROM asset_software x
        JOIN software s ON s.id=x.software_id WHERE x.asset_id=? ORDER BY s.name COLLATE NOCASE`, a.id),
      updates: db.all('SELECT * FROM asset_updates WHERE asset_id=? ORDER BY installed_on DESC', a.id),
      history: db.all('SELECT * FROM asset_history WHERE asset_id=? ORDER BY ts DESC, id DESC LIMIT 500', a.id),
      contracts: db.all(`SELECT c.* FROM contracts c JOIN contract_assets ca ON ca.contract_id=c.id WHERE ca.asset_id=? ORDER BY c.end_date`, a.id),
      relations: db.all(`SELECT r.id, r.rel_type, 'out' AS dir, b.id AS other_id, b.name AS other_name, b.type AS other_type, b.asset_tag AS other_tag
          FROM asset_relations r JOIN assets b ON b.id=r.to_asset WHERE r.from_asset=?
        UNION ALL SELECT r.id, r.rel_type, 'in', b.id, b.name, b.type, b.asset_tag
          FROM asset_relations r JOIN assets b ON b.id=r.from_asset WHERE r.to_asset=?`, a.id, a.id),
      alerts: db.all('SELECT * FROM alerts WHERE asset_id=? AND resolved_at IS NULL ORDER BY created_at DESC', a.id),
      checkout: openCheckout(a.id) || null,
    };
  });

  function updateAsset(id, rec, user) {
    const old = mustGet('assets', id);
    const names = { location_id: 'locations', department_id: 'departments', person_id: 'people' };
    const label = (f, v) => (v && names[f] ? db.get(`SELECT name FROM ${names[f]} WHERE id=?`, v)?.name ?? v : v);
    for (const [f, v] of Object.entries(rec)) {
      if (String(old[f] ?? '') === String(v ?? '')) continue;
      const kind = f === 'status' ? 'status' : f === 'person_id' ? 'assignment' : f === 'location_id' ? 'location' : 'edit';
      addHistory(db, id, kind, f.replace(/_id$/, ''), label(f, old[f]), label(f, v), user.username);
    }
    db.update('assets', id, { ...rec, updated_at: nowIso() });
  }

  r('PUT', '/api/assets/:id', 'tech', ({ params, body, user }) => {
    const rec = pick(body, ASSET_EDITABLE);
    if (rec.model_id) {
      const m = db.get('SELECT am.name, am.model_number, am.asset_type, mf.name AS mfr FROM asset_models am LEFT JOIN manufacturers mf ON mf.id=am.manufacturer_id WHERE am.id=?', rec.model_id);
      if (!m) throw bad('Unknown model');
      rec.model = [m.name, m.model_number && m.model_number !== m.name ? m.model_number : null].filter(Boolean).join(' ');
      if (m.mfr) rec.manufacturer = m.mfr;
      if (m.asset_type && !rec.type) rec.type = m.asset_type;
    }
    if (rec.supplier_id) rec.vendor = db.get('SELECT name FROM suppliers WHERE id=?', rec.supplier_id)?.name ?? rec.vendor;
    if (rec.name === null) throw bad('Name is required');
    if (rec.type && !ASSET_TYPES.includes(rec.type)) throw bad('Invalid type');
    if (rec.status && !ASSET_STATUSES.includes(rec.status)) throw bad('Invalid status');
    if (rec.asset_tag) {
      const dup = db.get('SELECT id FROM assets WHERE asset_tag=? AND id<>?', rec.asset_tag, params.id);
      if (dup) throw bad('Asset tag already in use');
    }
    db.tx(() => updateAsset(Number(params.id), rec, user));
    audit(user, 'update', 'asset', params.id, Object.keys(rec).join(','));
    scheduleAlerts();
    return { ok: true };
  });
  r('DELETE', '/api/assets/:id', 'tech', ({ params, user }) => {
    const a = mustGet('assets', params.id);
    db.run('DELETE FROM assets WHERE id=?', a.id);
    audit(user, 'delete', 'asset', a.id, a.name);
    return { ok: true };
  });
  r('POST', '/api/assets/:id/scan', 'tech', ({ params }) => {
    const n = db.run('UPDATE agents SET scan_requested=1 WHERE asset_id=?', params.id).changes;
    if (!n) throw bad('This asset has no agent');
    return { ok: true };
  });
  r('POST', '/api/assets/:id/notes', 'tech', ({ params, body, user }) => {
    mustGet('assets', params.id);
    const text = String(body.text || '').trim();
    if (!text) throw bad('Note text is required');
    addHistory(db, Number(params.id), body.kind === 'maintenance' ? 'maintenance' : 'note', null, null, text, user.username);
    return { ok: true };
  });
  r('POST', '/api/assets/:id/relations', 'tech', ({ params, body, user }) => {
    mustGet('assets', params.id); mustGet('assets', body.to_asset);
    if (Number(body.to_asset) === Number(params.id)) throw bad('An asset cannot relate to itself');
    db.run('INSERT OR IGNORE INTO asset_relations(from_asset,to_asset,rel_type) VALUES(?,?,?)', params.id, body.to_asset, String(body.rel_type || 'connected_to'));
    addHistory(db, Number(params.id), 'relation', String(body.rel_type), null, db.get('SELECT name FROM assets WHERE id=?', body.to_asset).name, user.username);
    return { ok: true };
  });
  r('DELETE', '/api/relations/:id', 'tech', ({ params }) => { db.run('DELETE FROM asset_relations WHERE id=?', params.id); return { ok: true }; });

  // ======================= SOFTWARE =======================
  r('GET', '/api/software', 'viewer', ({ query }) => {
    const where = [], p = [];
    if (query.q) { where.push('(s.name LIKE ? OR s.publisher LIKE ?)'); p.push(`%${query.q}%`, `%${query.q}%`); }
    if (query.status) { where.push('s.status=?'); p.push(query.status); }
    const w = where.length ? 'WHERE ' + where.join(' AND ') : '';
    const sort = { installs: 'installs DESC', name: 's.name COLLATE NOCASE', publisher: 's.publisher COLLATE NOCASE' }[query.sort] || 'installs DESC';
    const limit = Math.min(Number(query.limit) || 100, 1000), page = Math.max(Number(query.page) || 1, 1);
    const total = db.get(`SELECT COUNT(*) AS n FROM software s ${w}`, ...p).n;
    const rows = db.all(`SELECT s.*, COUNT(DISTINCT x.asset_id) AS installs, COUNT(DISTINCT x.version) AS versions
      FROM software s LEFT JOIN asset_software x ON x.software_id=s.id ${w} GROUP BY s.id ORDER BY ${sort} LIMIT ? OFFSET ?`, ...p, limit, (page - 1) * limit);
    return { total, page, limit, rows };
  });
  r('GET', '/api/software/:id', 'viewer', ({ params }) => {
    const s = mustGet('software', params.id);
    return {
      ...s,
      installs: db.all(`SELECT a.id, a.name, a.asset_tag, a.last_user, a.status, x.version, x.install_date FROM asset_software x
        JOIN assets a ON a.id=x.asset_id WHERE x.software_id=? ORDER BY a.name`, s.id),
      versions: db.all('SELECT version, COUNT(*) AS n FROM asset_software WHERE software_id=? GROUP BY version ORDER BY n DESC', s.id),
    };
  });
  r('PUT', '/api/software/:id', 'tech', ({ params, body, user }) => {
    mustGet('software', params.id);
    const rec = pick(body, ['status', 'category', 'notes']);
    if (rec.status && !['neutral', 'authorized', 'prohibited'].includes(rec.status)) throw bad('Invalid status');
    db.update('software', params.id, rec);
    audit(user, 'update', 'software', params.id, JSON.stringify(rec));
    scheduleAlerts();
    return { ok: true };
  });

  // ======================= LICENSES =======================
  const LIC_FIELDS = ['name', 'software_match', 'vendor', 'license_type', 'seats', 'cost', 'purchase_date', 'expiry_date', 'license_key', 'notes'];
  // License keys are encrypted at rest with the master key.
  const licIn = (body) => { const rec = pick(body, LIC_FIELDS); if ('license_key' in rec) rec.license_key = vault.encrypt(rec.license_key); return rec; };
  r('GET', '/api/licenses', 'viewer', () => db.all('SELECT * FROM licenses ORDER BY name').map((l) => {
    const { used } = licenseUsage(db, l);
    return { ...l, license_key: l.license_key ? '••••••' : null, used, compliance: licenseStatus(l, used) };
  }));
  r('GET', '/api/licenses/:id', 'viewer', ({ params, user }) => {
    const l = mustGet('licenses', params.id);
    const u = licenseUsage(db, l);
    return { ...l, license_key: ROLES[user.role] >= ROLES.tech ? vault.decrypt(l.license_key) : (l.license_key ? '••••••' : null), used: u.used, compliance: licenseStatus(l, u.used), installs: u.assets };
  });
  r('POST', '/api/licenses', 'tech', ({ body, user }) => {
    const rec = licIn(body);
    if (!rec.name) throw bad('Name is required');
    const id = db.insert('licenses', rec);
    audit(user, 'create', 'license', id, rec.name); scheduleAlerts();
    return { id };
  });
  r('PUT', '/api/licenses/:id', 'tech', ({ params, body, user }) => {
    mustGet('licenses', params.id);
    db.update('licenses', params.id, licIn(body));
    audit(user, 'update', 'license', params.id); scheduleAlerts();
    return { ok: true };
  });
  r('DELETE', '/api/licenses/:id', 'tech', ({ params, user }) => {
    db.run('DELETE FROM licenses WHERE id=?', params.id);
    audit(user, 'delete', 'license', params.id); scheduleAlerts();
    return { ok: true };
  });

  // ======================= CONTRACTS =======================
  const CON_FIELDS = ['name', 'vendor', 'contract_type', 'number', 'start_date', 'end_date', 'cost', 'renewal', 'notes'];
  r('GET', '/api/contracts', 'viewer', () => db.all(`SELECT c.*, (SELECT COUNT(*) FROM contract_assets WHERE contract_id=c.id) AS asset_count
    FROM contracts c ORDER BY c.end_date IS NULL, c.end_date`));
  r('GET', '/api/contracts/:id', 'viewer', ({ params }) => ({
    ...mustGet('contracts', params.id),
    assets: db.all(`SELECT a.id, a.name, a.asset_tag, a.type, a.status FROM contract_assets ca JOIN assets a ON a.id=ca.asset_id
      WHERE ca.contract_id=? ORDER BY a.name`, params.id),
  }));
  r('POST', '/api/contracts', 'tech', ({ body, user }) => {
    const rec = pick(body, CON_FIELDS);
    if (!rec.name) throw bad('Name is required');
    const id = db.insert('contracts', rec);
    audit(user, 'create', 'contract', id, rec.name); scheduleAlerts();
    return { id };
  });
  r('PUT', '/api/contracts/:id', 'tech', ({ params, body, user }) => {
    mustGet('contracts', params.id);
    db.update('contracts', params.id, pick(body, CON_FIELDS));
    audit(user, 'update', 'contract', params.id); scheduleAlerts();
    return { ok: true };
  });
  r('DELETE', '/api/contracts/:id', 'tech', ({ params, user }) => {
    db.run('DELETE FROM contracts WHERE id=?', params.id);
    audit(user, 'delete', 'contract', params.id); scheduleAlerts();
    return { ok: true };
  });
  r('POST', '/api/contracts/:id/assets', 'tech', ({ params, body, user }) => {
    mustGet('contracts', params.id);
    db.tx(() => (body.asset_ids || []).forEach((aid) => db.run('INSERT OR IGNORE INTO contract_assets(contract_id,asset_id) VALUES(?,?)', params.id, aid)));
    audit(user, 'link_assets', 'contract', params.id, (body.asset_ids || []).join(','));
    return { ok: true };
  });
  r('DELETE', '/api/contracts/:id/assets/:assetId', 'tech', ({ params }) => {
    db.run('DELETE FROM contract_assets WHERE contract_id=? AND asset_id=?', params.id, params.assetId);
    return { ok: true };
  });

  // ======================= ORG DATA (people / locations / departments / custom fields) =======================
  const simpleCrud = (base, table, fields, listSql, role = 'tech') => {
    r('GET', `/api/${base}`, 'viewer', () => db.all(listSql));
    r('GET', `/api/${base}/:id`, 'viewer', ({ params }) => {
      const row = mustGet(table, params.id);
      const fk = { people: 'person_id', locations: 'location_id', departments: 'department_id', companies: 'company_id', suppliers: 'supplier_id', asset_models: 'model_id' }[table];
      if (fk) row.assets = db.all(`SELECT id, name, asset_tag, type, status FROM assets WHERE ${fk}=? ORDER BY name`, row.id);
      return row;
    });
    r('POST', `/api/${base}`, role, ({ body, user }) => {
      const rec = pick(body, fields);
      if (!rec.name) throw bad('Name is required');
      const id = db.insert(table, rec);
      audit(user, 'create', table, id, rec.name);
      return { id };
    });
    r('PUT', `/api/${base}/:id`, role, ({ params, body, user }) => {
      mustGet(table, params.id);
      db.update(table, params.id, pick(body, fields));
      audit(user, 'update', table, params.id);
      return { ok: true };
    });
    r('DELETE', `/api/${base}/:id`, role, ({ params, user }) => {
      db.run(`DELETE FROM ${table} WHERE id=?`, params.id);
      audit(user, 'delete', table, params.id);
      return { ok: true };
    });
  };
  simpleCrud('people', 'people', ['name', 'email', 'phone', 'title', 'username', 'employee_number', 'company_id', 'department_id', 'location_id', 'notes'],
    `SELECT p.*, d.name AS department, l.name AS location, (SELECT COUNT(*) FROM assets WHERE person_id=p.id) AS asset_count
     FROM people p LEFT JOIN departments d ON d.id=p.department_id LEFT JOIN locations l ON l.id=p.location_id ORDER BY p.name`);
  simpleCrud('locations', 'locations', ['name', 'address', 'notes', 'lat', 'lng'],
    'SELECT l.*, (SELECT COUNT(*) FROM assets WHERE location_id=l.id) AS asset_count FROM locations l ORDER BY name');
  simpleCrud('departments', 'departments', ['name', 'notes'],
    'SELECT d.*, (SELECT COUNT(*) FROM assets WHERE department_id=d.id) AS asset_count FROM departments d ORDER BY name');
  simpleCrud('custom-fields', 'custom_fields', ['name', 'field_type', 'applies_to'], 'SELECT * FROM custom_fields ORDER BY id', 'admin');

  // ======================= ALERTS =======================
  r('GET', '/api/alerts', 'viewer', ({ query }) => db.all(`SELECT al.*, a.name AS asset_name FROM alerts al LEFT JOIN assets a ON a.id=al.asset_id
    WHERE ${query.state === 'resolved' ? 'al.resolved_at IS NOT NULL' : 'al.resolved_at IS NULL'}
    ORDER BY CASE al.severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, al.created_at DESC LIMIT 1000`));
  r('POST', '/api/alerts/:id/ack', 'tech', ({ params }) => { db.run('UPDATE alerts SET acknowledged=1 WHERE id=?', params.id); return { ok: true }; });
  r('POST', '/api/alerts/refresh', 'tech', () => { evaluateAlerts(db); return { ok: true }; });

  // ======================= DISCOVERY =======================
  r('GET', '/api/discovery', 'viewer', () => ({
    job: discovery.status(),
    results: db.all(`SELECT r.*, a.name AS asset_name FROM discovery_results r LEFT JOIN assets a ON a.id=r.asset_id ORDER BY r.last_seen DESC, r.ip LIMIT 5000`),
  }));
  r('POST', '/api/discovery/scan', 'tech', ({ body, user }) => {
    try { const job = discovery.start(body.targets, user.username); audit(user, 'scan', 'network', null, body.targets); return job; }
    catch (e) { throw bad(e.message); }
  });
  r('POST', '/api/discovery/:id/import', 'tech', ({ params, user }) => {
    const d = mustGet('discovery_results', params.id);
    if (d.asset_id) throw bad('Already linked to an asset');
    const id = db.tx(() => {
      const nid = db.insert('assets', { name: d.hostname?.split('.')[0] || d.ip, hostname: d.hostname, ip: d.ip, mac: d.mac, type: d.guess_type || 'other', source: 'discovery' });
      db.run('UPDATE assets SET asset_tag=? WHERE id=?', assetTag(db, nid), nid);
      db.run('UPDATE discovery_results SET asset_id=? WHERE id=?', nid, d.id);
      addHistory(db, nid, 'created', null, null, `Imported from network discovery (${d.ip})`, user.username);
      return nid;
    });
    audit(user, 'import', 'asset', id, `discovery ${d.ip}`);
    return { id };
  });
  r('DELETE', '/api/discovery/:id', 'tech', ({ params }) => { db.run('DELETE FROM discovery_results WHERE id=?', params.id); return { ok: true }; });

  // ======================= DASHBOARD / SEARCH =======================
  r('GET', '/api/dashboard', 'viewer', () => {
    const cnt = (sql, ...p) => db.get(sql, ...p).n;
    const onlineCut = new Date(Date.now() - ONLINE_MS).toISOString();
    const lic = db.all('SELECT * FROM licenses').map((l) => licenseStatus(l, licenseUsage(db, l).used));
    return {
      assets: cnt('SELECT COUNT(*) AS n FROM assets'),
      agents: cnt('SELECT COUNT(*) AS n FROM agents'),
      agents_online: cnt('SELECT COUNT(*) AS n FROM agents WHERE last_heartbeat >= ?', onlineCut),
      software: cnt('SELECT COUNT(DISTINCT software_id) AS n FROM asset_software'),
      unmanaged: cnt('SELECT COUNT(*) AS n FROM discovery_results WHERE asset_id IS NULL'),
      alerts: db.all("SELECT severity, COUNT(*) AS n FROM alerts WHERE resolved_at IS NULL GROUP BY severity"),
      warranty_90: cnt(`SELECT COUNT(*) AS n FROM assets WHERE warranty_end >= ? AND warranty_end <= ? AND status NOT IN ('retired','disposed')`,
        today(), new Date(Date.now() + 90 * 86400000).toISOString().slice(0, 10)),
      licenses: { total: lic.length, over: lic.filter((s) => s === 'over').length, expired: lic.filter((s) => s === 'expired').length },
      checked_out: cnt('SELECT COUNT(*) AS n FROM asset_checkouts WHERE in_at IS NULL'),
      pending_accept: cnt("SELECT COUNT(*) AS n FROM asset_checkouts WHERE in_at IS NULL AND accept_status='pending'"),
      audit_due: cnt("SELECT COUNT(*) AS n FROM assets WHERE next_audit_date IS NOT NULL AND next_audit_date < ? AND status NOT IN ('retired','disposed','lost')", today()),
      stock_items: cnt('SELECT COUNT(*) AS n FROM stock_items'),
      low_stock: db.all(`SELECT s.qty_total - COALESCE((SELECT SUM(qty) FROM stock_moves WHERE item_id=s.id AND action='checkout' AND returned=0),0) AS av, s.min_qty
        FROM stock_items s WHERE s.min_qty > 0`).filter((x) => x.av <= x.min_qty).length,
      overdue: cnt('SELECT COUNT(*) AS n FROM asset_checkouts WHERE in_at IS NULL AND due_at IS NOT NULL AND due_at < ?', today()),
      total_value: db.get("SELECT COALESCE(SUM(purchase_cost),0) AS v FROM assets WHERE status NOT IN ('disposed','lost')").v,
      by_type: db.all('SELECT type AS k, COUNT(*) AS n FROM assets GROUP BY type ORDER BY n DESC'),
      by_status: db.all('SELECT status AS k, COUNT(*) AS n FROM assets GROUP BY status ORDER BY n DESC'),
      by_os: db.all("SELECT COALESCE(os_name,'Unknown') AS k, COUNT(*) AS n FROM assets WHERE type IN ('workstation','laptop','server','virtual_machine') GROUP BY k ORDER BY n DESC LIMIT 8"),
      by_manufacturer: db.all("SELECT COALESCE(manufacturer,'Unknown') AS k, COUNT(*) AS n FROM assets GROUP BY k ORDER BY n DESC LIMIT 8"),
      top_software: db.all(`SELECT s.id, s.name, COUNT(DISTINCT x.asset_id) AS n FROM asset_software x JOIN software s ON s.id=x.software_id
        GROUP BY s.id ORDER BY n DESC LIMIT 8`),
      recent_changes: db.all(`SELECT h.*, a.name AS asset_name FROM asset_history h JOIN assets a ON a.id=h.asset_id
        WHERE h.kind IN ('hardware','software','os','created','status','assignment','security') ORDER BY h.ts DESC, h.id DESC LIMIT 15`),
    };
  });
  r('GET', '/api/search', 'viewer', ({ query }) => {
    const like = `%${query.q || ''}%`;
    if (!query.q || String(query.q).length < 2) return { assets: [], people: [], software: [] };
    return {
      assets: db.all(`SELECT id, name, asset_tag, type, serial, ip FROM assets WHERE name LIKE ? OR asset_tag LIKE ? OR serial LIKE ?
        OR hostname LIKE ? OR ip LIKE ? OR last_user LIKE ? OR mac LIKE ? ORDER BY name LIMIT 10`, like, like, like, like, like, like, like),
      people: db.all('SELECT id, name, email FROM people WHERE name LIKE ? OR email LIKE ? OR username LIKE ? ORDER BY name LIMIT 5', like, like, like),
      software: db.all('SELECT id, name, publisher FROM software WHERE name LIKE ? ORDER BY name LIMIT 5', like),
    };
  });

  // ======================= REPORTS =======================
  const days = (q, d) => Math.max(0, Math.min(3650, Number(q.days) || d));
  const plusDays = (n) => new Date(Date.now() + n * 86400000).toISOString().slice(0, 10);
  const minusIso = (n) => new Date(Date.now() - n * 86400000).toISOString();
  const groupBy = (title, expr, join = '') => ({
    title, group: 'Inventory', chart: true,
    columns: [{ key: 'k', label: title.replace('Assets by ', '') }, { key: 'n', label: 'Assets' }],
    rows: () => db.all(`SELECT COALESCE(${expr}, 'Unassigned') AS k, COUNT(*) AS n FROM assets a ${join} GROUP BY k ORDER BY n DESC`),
  });
  const REPORTS = {
    assets_by_type: groupBy('Assets by type', 'a.type'),
    assets_by_status: groupBy('Assets by status', 'a.status'),
    assets_by_os: groupBy('Assets by operating system', 'a.os_name'),
    assets_by_manufacturer: groupBy('Assets by manufacturer', 'a.manufacturer'),
    assets_by_model: groupBy('Assets by model', "a.manufacturer || ' ' || a.model"),
    assets_by_location: groupBy('Assets by location', 'l.name', 'LEFT JOIN locations l ON l.id=a.location_id'),
    assets_by_department: groupBy('Assets by department', 'd.name', 'LEFT JOIN departments d ON d.id=a.department_id'),
    warranty_expiring: {
      title: 'Warranty expiring', group: 'Lifecycle', param: { name: 'days', def: 90 },
      columns: [{ key: 'asset_tag' }, { key: 'name' }, { key: 'model' }, { key: 'serial' }, { key: 'warranty_end' }, { key: 'status' }],
      rows: (q) => db.all(`SELECT id, asset_tag, name, model, serial, warranty_end, status FROM assets WHERE warranty_end IS NOT NULL AND warranty_end <> ''
        AND warranty_end <= ? AND status NOT IN ('retired','disposed') ORDER BY warranty_end`, plusDays(days(q, 90))),
    },
    stale_agents: {
      title: 'Agents not reporting', group: 'Agents', param: { name: 'days', def: 7 },
      columns: [{ key: 'asset_tag' }, { key: 'name' }, { key: 'last_user' }, { key: 'last_heartbeat', label: 'Last contact' }, { key: 'version' }],
      rows: (q) => db.all(`SELECT a.id, a.asset_tag, a.name, a.last_user, g.last_heartbeat, g.version FROM agents g JOIN assets a ON a.id=g.asset_id
        WHERE COALESCE(g.last_heartbeat, g.enrolled_at) < ? ORDER BY g.last_heartbeat`, minusIso(days(q, 7))),
    },
    agent_versions: {
      title: 'Agent versions', group: 'Agents', chart: true,
      columns: [{ key: 'k', label: 'Version' }, { key: 'n', label: 'Agents' }],
      rows: () => db.all("SELECT COALESCE(version,'unknown') AS k, COUNT(*) AS n FROM agents GROUP BY k ORDER BY n DESC"),
    },
    unmanaged_devices: {
      title: 'Unmanaged network devices', group: 'Discovery',
      columns: [{ key: 'ip' }, { key: 'hostname' }, { key: 'mac' }, { key: 'guess_type', label: 'Probable type' }, { key: 'open_ports' }, { key: 'last_seen' }],
      rows: () => db.all('SELECT * FROM discovery_results WHERE asset_id IS NULL ORDER BY ip'),
    },
    software_installs: {
      title: 'Software install counts', group: 'Software',
      columns: [{ key: 'name' }, { key: 'publisher' }, { key: 'status' }, { key: 'installs' }, { key: 'versions' }],
      rows: () => db.all(`SELECT s.name, s.publisher, s.status, COUNT(DISTINCT x.asset_id) AS installs, COUNT(DISTINCT x.version) AS versions
        FROM software s JOIN asset_software x ON x.software_id=s.id GROUP BY s.id ORDER BY installs DESC`),
    },
    prohibited_installs: {
      title: 'Prohibited software installations', group: 'Software',
      columns: [{ key: 'asset_tag' }, { key: 'asset' }, { key: 'last_user' }, { key: 'software' }, { key: 'version' }],
      rows: () => db.all(`SELECT a.id, a.asset_tag, a.name AS asset, a.last_user, s.name AS software, x.version FROM asset_software x
        JOIN software s ON s.id=x.software_id JOIN assets a ON a.id=x.asset_id WHERE s.status='prohibited' ORDER BY s.name, a.name`),
    },
    software_changes: {
      title: 'Software changes', group: 'Software', param: { name: 'days', def: 30 },
      columns: [{ key: 'ts', label: 'When' }, { key: 'asset' }, { key: 'field', label: 'Change' }, { key: 'new_value', label: 'Software' }, { key: 'old_value', label: 'Previous' }],
      rows: (q) => db.all(`SELECT h.ts, a.id, a.name AS asset, h.field, h.new_value, h.old_value FROM asset_history h JOIN assets a ON a.id=h.asset_id
        WHERE h.kind='software' AND h.ts >= ? ORDER BY h.ts DESC LIMIT 5000`, minusIso(days(q, 30))),
    },
    hardware_changes: {
      title: 'Hardware & OS changes', group: 'Inventory', param: { name: 'days', def: 30 },
      columns: [{ key: 'ts', label: 'When' }, { key: 'asset' }, { key: 'field' }, { key: 'old_value', label: 'Before' }, { key: 'new_value', label: 'After' }],
      rows: (q) => db.all(`SELECT h.ts, a.id, a.name AS asset, h.field, h.old_value, h.new_value FROM asset_history h JOIN assets a ON a.id=h.asset_id
        WHERE h.kind IN ('hardware','os') AND h.ts >= ? ORDER BY h.ts DESC LIMIT 5000`, minusIso(days(q, 30))),
    },
    license_compliance: {
      title: 'License compliance', group: 'Software',
      columns: [{ key: 'name' }, { key: 'vendor' }, { key: 'license_type', label: 'Type' }, { key: 'seats' }, { key: 'used' }, { key: 'available' }, { key: 'compliance' }, { key: 'expiry_date' }],
      rows: () => db.all('SELECT * FROM licenses ORDER BY name').map((l) => {
        const { used } = licenseUsage(db, l);
        return { ...l, used, available: l.seats === null ? '∞' : l.seats - used, compliance: licenseStatus(l, used) };
      }),
    },
    low_disk: {
      title: 'Low disk space', group: 'Hardware', param: { name: 'pct', def: 15 },
      columns: [{ key: 'asset' }, { key: 'drive' }, { key: 'size_gb' }, { key: 'free_gb' }, { key: 'free_pct', label: 'Free %' }],
      rows: (q) => db.all(`SELECT a.id, a.name AS asset, d.name AS drive, d.size_gb, d.free_gb, ROUND(d.free_gb*100.0/d.size_gb,1) AS free_pct
        FROM asset_disks d JOIN assets a ON a.id=d.asset_id WHERE d.size_gb>1 AND d.free_gb*100.0/d.size_gb < ? ORDER BY free_pct`, Number(q.pct) || 15),
    },
    low_ram: {
      title: 'Computers with low memory', group: 'Hardware', param: { name: 'gb', def: 8 },
      columns: [{ key: 'asset_tag' }, { key: 'name' }, { key: 'model' }, { key: 'ram_gb', label: 'RAM (GB)' }, { key: 'last_user' }],
      rows: (q) => db.all(`SELECT id, asset_tag, name, model, ROUND(ram_mb/1024.0,1) AS ram_gb, last_user FROM assets
        WHERE ram_mb IS NOT NULL AND ram_mb < ? ORDER BY ram_mb`, (Number(q.gb) || 8) * 1024 - 256),
    },
    security_posture: {
      title: 'Security posture (antivirus / disk encryption)', group: 'Hardware',
      columns: [{ key: 'asset_tag' }, { key: 'name' }, { key: 'os_name' }, { key: 'antivirus' }, { key: 'encryption' }],
      rows: () => db.all(`SELECT a.id, a.asset_tag, a.name, a.os_name, COALESCE(a.antivirus,'— none reported —') AS antivirus,
        COALESCE(a.encryption,'— none reported —') AS encryption FROM assets a JOIN agents g ON g.asset_id=a.id ORDER BY a.name`),
    },
    patch_compliance: {
      title: 'Patch compliance (Windows updates)', group: 'Security', param: { name: 'days', def: 45 },
      columns: [{ key: 'asset_tag' }, { key: 'name' }, { key: 'os_name', label: 'OS' }, { key: 'os_build', label: 'Build' }, { key: 'last_patch', label: 'Last update installed' }, { key: 'patches', label: 'Updates', num: true }, { key: 'state', label: 'Status' }],
      rows: (q) => {
        const cut = new Date(Date.now() - days(q, 45) * 86400000).toISOString().slice(0, 10);
        return db.all(`SELECT a.id, a.asset_tag, a.name, a.os_name, a.os_build, MAX(u.installed_on) AS last_patch, COUNT(u.hotfix_id) AS patches
          FROM assets a JOIN agents g ON g.asset_id=a.id LEFT JOIN asset_updates u ON u.asset_id=a.id
          WHERE a.status NOT IN ('retired','disposed') GROUP BY a.id ORDER BY last_patch`).map((r0) => ({ ...r0, state: !r0.last_patch ? 'unknown' : r0.last_patch < cut ? 'non-compliant' : 'compliant' }));
      },
    },
    checkouts_overdue: {
      title: 'Overdue check-outs', group: 'Lifecycle',
      columns: [{ key: 'asset_tag' }, { key: 'name' }, { key: 'person', label: 'Checked out to' }, { key: 'out_at', label: 'Since' }, { key: 'due_at', label: 'Due' }],
      rows: () => db.all(`SELECT a.id, a.asset_tag, a.name, p.name AS person, substr(c.out_at,1,10) AS out_at, c.due_at FROM asset_checkouts c
        JOIN assets a ON a.id=c.asset_id LEFT JOIN people p ON p.id=c.person_id WHERE c.in_at IS NULL AND c.due_at < ? ORDER BY c.due_at`, today()),
    },
    audit_due: {
      title: 'Physical audit due', group: 'Lifecycle', param: { name: 'days', def: 30 },
      columns: [{ key: 'asset_tag' }, { key: 'name' }, { key: 'location' }, { key: 'last_audit', label: 'Last audited' }, { key: 'next_audit_date', label: 'Due' }, { key: 'status' }],
      rows: (q) => db.all(`SELECT a.id, a.asset_tag, a.name, l.name AS location, substr(a.last_audit_at,1,10) AS last_audit, COALESCE(a.next_audit_date,'never audited') AS next_audit_date, a.status
        FROM assets a LEFT JOIN locations l ON l.id=a.location_id WHERE a.status NOT IN ('retired','disposed','lost')
        AND (a.next_audit_date IS NULL OR a.next_audit_date <= ?) ORDER BY a.next_audit_date IS NOT NULL, a.next_audit_date`, plusDays(days(q, 30))),
    },
    stock_levels: {
      title: 'Stock levels', group: 'Inventory',
      columns: [{ key: 'name' }, { key: 'kind' }, { key: 'category' }, { key: 'location' }, { key: 'qty_total', label: 'Total', num: true }, { key: 'checked_out', label: 'Out', num: true }, { key: 'available', label: 'Available', num: true }, { key: 'min_qty', label: 'Minimum', num: true }, { key: 'state', label: 'Status' }],
      rows: () => db.all(`SELECT s.name, s.kind, s.category, l.name AS location, s.qty_total, s.min_qty,
          COALESCE((SELECT SUM(qty) FROM stock_moves WHERE item_id=s.id AND action='checkout' AND returned=0),0) AS checked_out
          FROM stock_items s LEFT JOIN locations l ON l.id=s.location_id ORDER BY s.name`)
        .map((r0) => ({ ...r0, available: r0.qty_total - r0.checked_out, state: r0.min_qty > 0 && r0.qty_total - r0.checked_out <= r0.min_qty ? 'low' : 'ok' })),
    },
    pending_acceptance: {
      title: 'Assignments awaiting acceptance', group: 'Lifecycle',
      columns: [{ key: 'asset_tag' }, { key: 'name' }, { key: 'person', label: 'Assigned to' }, { key: 'out_at', label: 'Since' }, { key: 'accept_status', label: 'Status' }],
      rows: () => db.all(`SELECT a.id, a.asset_tag, a.name, p.name AS person, substr(c.out_at,1,10) AS out_at, c.accept_status FROM asset_checkouts c
        JOIN assets a ON a.id=c.asset_id LEFT JOIN people p ON p.id=c.person_id WHERE c.in_at IS NULL AND c.accept_status IN ('pending','declined') ORDER BY c.out_at`),
    },
    depreciation: {
      title: 'Asset value & depreciation', group: 'Financial',
      columns: [{ key: 'asset_tag' }, { key: 'name' }, { key: 'type' }, { key: 'purchase_date' }, { key: 'purchase_cost' }, { key: 'age_years', label: 'Age (yrs)' }, { key: 'current_value', label: 'Book value' }],
      rows: () => {
        const life = Number(db.setting('depreciation_years', 4)) || 4;
        return db.all(`SELECT id, asset_tag, name, type, purchase_date, purchase_cost FROM assets WHERE purchase_cost IS NOT NULL
          AND status NOT IN ('disposed','lost') ORDER BY purchase_date`).map((a) => {
          const age = a.purchase_date ? (Date.now() - Date.parse(a.purchase_date)) / (365.25 * 86400000) : 0;
          return { ...a, age_years: Math.round(age * 10) / 10, current_value: Math.round(a.purchase_cost * Math.max(0, 1 - age / life) * 100) / 100 };
        });
      },
    },
    cost_by_type: {
      title: 'Spend by asset type', group: 'Financial', chart: true,
      columns: [{ key: 'k', label: 'Type' }, { key: 'n', label: 'Total cost' }],
      rows: () => db.all("SELECT type AS k, ROUND(SUM(purchase_cost),2) AS n FROM assets WHERE purchase_cost IS NOT NULL GROUP BY type ORDER BY n DESC"),
    },
  };
  r('GET', '/api/reports', 'viewer', () => Object.entries(REPORTS).map(([id, rp]) => ({ id, title: rp.title, group: rp.group, param: rp.param || null })));
  r('GET', '/api/reports/:name', 'viewer', ({ params, query, res }) => {
    const rp = REPORTS[params.name];
    if (!rp) throw notFound('Unknown report');
    const rows = rp.rows(query);
    if (query.format === 'csv') {
      return send(res, 200, toCsv(rp.columns, rows), { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': `attachment; filename="${params.name}-${today()}.csv"` });
    }
    return { id: params.name, title: rp.title, chart: !!rp.chart, param: rp.param || null, columns: rp.columns, rows };
  });

  // ======================= ADMIN: settings, users, audit =======================
  const SETTING_KEYS = ['org_name', 'asset_tag_prefix', 'agent_interval_min', 'offline_days', 'low_disk_pct', 'warranty_alert_days',
    'license_alert_days', 'contract_alert_days', 'depreciation_years', 'currency', 'public_url',
    'session_idle_min', 'session_max_hours', 'require_2fa_admins',
    'monitoring_enabled', 'activity_enabled', 'screenshot_enabled', 'screenshot_interval_min', 'idle_threshold_sec',
    'location_enabled', 'monitoring_retention_days', 'monitoring_notice', 'require_acceptance', 'audit_interval_months', 'eula_text'];
  r('GET', '/api/settings', 'admin', () => Object.fromEntries(SETTING_KEYS.map((k) => [k, db.setting(k, '')])));
  r('PUT', '/api/settings', 'admin', ({ body, user }) => {
    for (const k of SETTING_KEYS) if (k in body) db.setSetting(k, body[k] ?? '');
    const iv = Number(db.setting('agent_interval_min'));
    if (!(iv >= 5)) db.setSetting('agent_interval_min', 5);
    audit(user, 'update', 'settings', null, Object.keys(body).join(','));
    scheduleAlerts();
    return { ok: true };
  });
  r('POST', '/api/settings/enrollment-key', 'admin', ({ user }) => {
    db.setSetting('enrollment_key', crypto.randomBytes(16).toString('hex'));
    audit(user, 'rotate', 'enrollment_key', null);
    return { ok: true };
  });

  r('GET', '/api/users', 'admin', () => db.all(`SELECT u.id, u.username, u.name, u.email, u.role, u.created_at, u.last_login, u.totp_enabled, u.group_id, u.person_id, g.name AS group_name, p.name AS person_name
    FROM users u LEFT JOIN perm_groups g ON g.id=u.group_id LEFT JOIN people p ON p.id=u.person_id ORDER BY u.username`));
  r('POST', '/api/users', 'admin', ({ body, user }) => {
    if (!body.username || !body.password) throw bad('Username and password are required');
    const problem = passwordProblem(body.password, body.username);
    if (problem) throw bad(problem);
    if (!(body.role in ROLES)) throw bad('Invalid role');
    if (db.get('SELECT id FROM users WHERE username=?', body.username)) throw bad('Username already exists');
    const id = db.insert('users', { username: body.username, name: body.name || null, email: body.email || null, role: body.role, pass_hash: hashPassword(body.password), must_change: 1, password_changed_at: nowIso(),
      group_id: body.group_id ? Number(body.group_id) : null, person_id: body.person_id ? Number(body.person_id) : null });
    audit(user, 'create', 'user', id, body.username);
    return { id };
  });
  r('PUT', '/api/users/:id', 'admin', ({ params, body, user }) => {
    const u = mustGet('users', params.id);
    const rec = pick(body, ['name', 'email', 'role', 'group_id', 'person_id']);
    if (rec.role && !(rec.role in ROLES)) throw bad('Invalid role');
    if (u.role === 'admin' && rec.role && rec.role !== 'admin' && db.get("SELECT COUNT(*) AS n FROM users WHERE role='admin'").n < 2) throw bad('Cannot demote the last admin');
    if (body.password) {
      const problem = passwordProblem(body.password, u.username);
      if (problem) throw bad(problem);
      rec.pass_hash = hashPassword(body.password); rec.must_change = 1; rec.password_changed_at = nowIso();
      db.run('DELETE FROM sessions WHERE user_id=?', u.id);
    }
    if (body.reset_2fa) { rec.totp_enabled = 0; rec.totp_secret_enc = null; }
    db.update('users', u.id, rec);
    audit(user, 'update', 'user', u.id, Object.keys(rec).filter((k) => k !== 'pass_hash').join(',') + (body.password ? ',password' : ''));
    return { ok: true };
  });
  r('DELETE', '/api/users/:id', 'admin', ({ params, user }) => {
    if (Number(params.id) === user.id) throw bad('You cannot delete yourself');
    db.run('DELETE FROM users WHERE id=?', params.id);
    audit(user, 'delete', 'user', params.id);
    return { ok: true };
  });
  r('GET', '/api/audit', 'admin', ({ query }) => {
    const like = `%${query.q || ''}%`;
    return db.all('SELECT * FROM audit_log WHERE username LIKE ? OR action LIKE ? OR entity LIKE ? OR detail LIKE ? ORDER BY id DESC LIMIT 1000', like, like, like, like);
  });

  // ======================= MONITORING (activity / screenshots / location) =======================
  // Sensitive: restricted to technicians and admins.
  const monRange = (q) => {
    const day = /^\d{4}-\d\d-\d\d$/.test(q.day || '') ? q.day : null;
    if (day) return { from: `${day}T00:00:00.000Z`, to: `${day}T23:59:59.999Z`, day };
    const days = Math.max(1, Math.min(31, Number(q.days) || 1));
    return { from: new Date(Date.now() - days * 86400000).toISOString(), to: nowIso(), day: null };
  };
  const ACTIVE_MS = 6 * 60 * 1000;

  r('GET', '/api/monitoring', 'tech', () => {
    const activeCut = new Date(Date.now() - ACTIVE_MS).toISOString();
    const today = new Date().toISOString().slice(0, 10);
    return {
      policy: monitoring.policy(),
      settings: ['monitoring_enabled', 'activity_enabled', 'screenshot_enabled', 'screenshot_interval_min', 'idle_threshold_sec',
        'location_enabled', 'monitoring_retention_days', 'monitoring_notice'].reduce((o, k) => ((o[k] = db.setting(k, '')), o), {}),
      agents: db.get('SELECT COUNT(*) AS n FROM agents').n,
      active_now: db.all(`SELECT a.id, a.name, a.asset_tag, a.cur_app, a.cur_title, a.cur_os_user, a.activity_at, a.loc_label
        FROM assets a WHERE a.activity_at >= ? ORDER BY a.activity_at DESC`, activeCut),
      shots_today: db.get('SELECT COUNT(*) AS n FROM screenshots WHERE ts >= ?', `${today}T00:00:00Z`).n,
      top_apps: db.all(`SELECT app, category, SUM(active_seconds) AS secs, COUNT(DISTINCT asset_id) AS devices FROM activity_events
        WHERE ts >= ? AND app IS NOT NULL GROUP BY app ORDER BY secs DESC LIMIT 10`, `${today}T00:00:00Z`),
      by_category: db.all(`SELECT category AS k, SUM(active_seconds) AS n FROM activity_events WHERE ts >= ? GROUP BY category ORDER BY n DESC`, `${today}T00:00:00Z`),
      recent_shots: db.all(`SELECT s.id, s.asset_id, s.ts, s.app, s.title, a.name AS asset_name FROM screenshots s JOIN assets a ON a.id=s.asset_id
        ORDER BY s.ts DESC LIMIT 12`),
    };
  });

  r('GET', '/api/assets/:id/activity', 'tech', ({ params, query }) => {
    const a = mustGet('assets', params.id);
    const { from, to, day } = monRange(query);
    return {
      asset: { id: a.id, name: a.name, asset_tag: a.asset_tag, cur_app: a.cur_app, cur_title: a.cur_title, cur_os_user: a.cur_os_user, activity_at: a.activity_at },
      policy: monitoring.policy(), day: day || new Date().toISOString().slice(0, 10),
      days_available: db.all('SELECT DISTINCT substr(ts,1,10) AS day FROM activity_events WHERE asset_id=? ORDER BY day DESC LIMIT 60', a.id).map((r0) => r0.day),
      summary: db.get('SELECT COALESCE(SUM(active_seconds),0) AS active, COALESCE(SUM(seconds),0) AS total, COUNT(*) AS events FROM activity_events WHERE asset_id=? AND ts>=? AND ts<=?', a.id, from, to),
      by_app: db.all(`SELECT app, process, category, SUM(active_seconds) AS secs, COUNT(*) AS sessions FROM activity_events
        WHERE asset_id=? AND ts>=? AND ts<=? AND app IS NOT NULL GROUP BY app ORDER BY secs DESC LIMIT 40`, a.id, from, to),
      by_category: db.all(`SELECT category AS k, SUM(active_seconds) AS n FROM activity_events WHERE asset_id=? AND ts>=? AND ts<=? GROUP BY category ORDER BY n DESC`, a.id, from, to),
      timeline: db.all(`SELECT ts, end_ts, seconds, active_seconds, app, process, title, category, os_user FROM activity_events
        WHERE asset_id=? AND ts>=? AND ts<=? ORDER BY ts DESC LIMIT 500`, a.id, from, to),
      screenshots: db.all('SELECT id, ts, app, title, width, height, monitors, bytes FROM screenshots WHERE asset_id=? AND ts>=? AND ts<=? ORDER BY ts DESC LIMIT 200', a.id, from, to),
      locations: db.all('SELECT ts, method, ssid, bssid, public_ip, private_ip, lat, lng, accuracy, label FROM location_samples WHERE asset_id=? AND ts>=? AND ts<=? ORDER BY ts DESC LIMIT 100', a.id, from, to),
    };
  });

  r('GET', '/api/screenshots/:id/image', 'tech', ({ params, res, user }) => {
    const row = db.get('SELECT * FROM screenshots WHERE id=?', params.id);
    if (!row) throw notFound('Screenshot not found');
    const buf = monitoring.readScreenshot(row);
    if (!buf) throw notFound('Image unavailable');
    audit(user, 'view_screenshot', 'asset', row.asset_id, `shot ${row.id}`);
    send(res, 200, buf, { 'Content-Type': 'image/jpeg', 'Cache-Control': 'private, max-age=86400', 'Content-Disposition': `inline; filename="shot-${row.id}.jpg"` });
  });
  r('POST', '/api/assets/:id/screenshot', 'tech', ({ params }) => {
    const n = db.run('UPDATE agents SET scan_requested=2 WHERE asset_id=?', params.id).changes;
    if (!n) throw bad('This asset has no agent');
    return { ok: true };
  });
  r('DELETE', '/api/screenshots/:id', 'tech', ({ params, user }) => {
    const row = db.get('SELECT * FROM screenshots WHERE id=?', params.id);
    if (row) { try { fs.unlinkSync(path.join(monitoring.dir, row.file)); } catch { /* gone */ } db.run('DELETE FROM screenshots WHERE id=?', row.id); audit(user, 'delete', 'screenshot', row.id); }
    return { ok: true };
  });
  r('DELETE', '/api/assets/:id/activity', 'tech', ({ params, user }) => {
    const a = mustGet('assets', params.id);
    for (const s of db.all('SELECT file FROM screenshots WHERE asset_id=?', a.id)) { try { fs.unlinkSync(path.join(monitoring.dir, s.file)); } catch { /* gone */ } }
    db.tx(() => {
      db.run('DELETE FROM screenshots WHERE asset_id=?', a.id);
      db.run('DELETE FROM activity_events WHERE asset_id=?', a.id);
      db.run('DELETE FROM location_samples WHERE asset_id=?', a.id);
      db.run('UPDATE assets SET cur_app=NULL, cur_title=NULL, activity_at=NULL WHERE id=?', a.id);
    });
    audit(user, 'purge_activity', 'asset', a.id, a.name);
    return { ok: true };
  });

  // ======================= CHECK-OUT / CHECK-IN (to a person or a location, with acceptance) =======================
  const CO_SELECT = `SELECT c.*, p.name AS person, p.email, l.name AS location FROM asset_checkouts c
    LEFT JOIN people p ON p.id=c.person_id LEFT JOIN locations l ON l.id=c.location_id`;
  const openCheckout = (assetId) => db.get(`${CO_SELECT} WHERE c.asset_id=? AND c.in_at IS NULL ORDER BY c.id DESC LIMIT 1`, assetId);
  const hasPerm = (user, p) => (user?._perms || []).includes(p);
  function doCheckout(a, body, user) {
    if (openCheckout(a.id)) throw bad(`${a.name} is already checked out — check it in first`);
    if (['retired', 'disposed', 'lost'].includes(a.status)) throw bad(`${a.name} is ${a.status.replace('_', ' ')} and cannot be checked out`);
    if (body.due_at && !/^\d{4}-\d\d-\d\d$/.test(body.due_at)) throw bad('Invalid due date');
    const p = body.person_id ? mustGet('people', body.person_id) : null;
    const l = !p && body.location_id ? mustGet('locations', body.location_id) : null;
    if (!p && !l) throw bad('Choose a person or a location');
    // Acceptance is requested only when the person can sign in to the self-service portal.
    const needAccept = p && db.setting('require_acceptance') === '1' && db.get("SELECT id FROM users WHERE person_id=? AND role='user'", p.id);
    db.insert('asset_checkouts', { asset_id: a.id, person_id: p?.id ?? null, location_id: l?.id ?? null, out_at: nowIso(), due_at: body.due_at || null,
      out_by: user.username, out_notes: body.notes || null, accept_status: needAccept ? 'pending' : null });
    db.update('assets', a.id, p ? { person_id: p.id, status: 'in_use', updated_at: nowIso() } : { person_id: null, location_id: l.id, status: 'in_use', updated_at: nowIso() });
    addHistory(db, a.id, 'assignment', 'checked out', a.person_id ? db.get('SELECT name FROM people WHERE id=?', a.person_id)?.name : null,
      `${p ? p.name : `Location: ${l.name}`}${body.due_at ? ` (due ${body.due_at})` : ''}${needAccept ? ' — awaiting acceptance' : ''}`, user.username);
    return p ? p.name : l.name;
  }
  r('GET', '/api/assets/:id/checkouts', 'viewer', ({ params }) => ({
    current: openCheckout(params.id) || null,
    history: db.all(`${CO_SELECT} WHERE c.asset_id=? ORDER BY c.id DESC LIMIT 100`, params.id),
  }));
  r('POST', '/api/assets/:id/checkout', 'tech', ({ params, body, user }) => {
    const a = mustGet('assets', params.id);
    const to = db.tx(() => doCheckout(a, body, user));
    audit(user, 'checkout', 'asset', a.id, `${a.name} -> ${to}`);
    scheduleAlerts();
    return { ok: true };
  });
  r('POST', '/api/assets/bulk-checkout', 'tech', ({ body, user }) => {
    const ids = (body.ids || []).map(Number).filter(Boolean);
    if (!ids.length) throw bad('No assets selected');
    const done = [], errors = [];
    for (const id of ids) {
      try { const a = mustGet('assets', id); db.tx(() => doCheckout(a, body, user)); done.push(a.name); }
      catch (e) { errors.push(e.message); }
    }
    audit(user, 'bulk_checkout', 'asset', ids.join(','), `${done.length} checked out`);
    scheduleAlerts();
    return { ok: true, count: done.length, errors };
  });
  r('POST', '/api/assets/:id/checkin', 'tech', ({ params, body, user }) => {
    const a = mustGet('assets', params.id);
    const c = openCheckout(a.id);
    if (!c) throw bad('This asset is not checked out');
    const status = ASSET_STATUSES.includes(body.status) ? body.status : 'in_stock';
    db.tx(() => {
      db.run('UPDATE asset_checkouts SET in_at=?, in_by=?, in_notes=?, in_condition=? WHERE id=?', nowIso(), user.username, body.notes || null, body.condition || null, c.id);
      db.update('assets', a.id, { person_id: null, status, updated_at: nowIso() });
      addHistory(db, a.id, 'assignment', 'checked in', c.person || c.location, `Returned${body.condition ? ` — ${body.condition}` : ''}`, user.username);
    });
    audit(user, 'checkin', 'asset', a.id, `${a.name} from ${c.person || c.location || '?'}`);
    scheduleAlerts();
    return { ok: true };
  });
  r('GET', '/api/checkouts', 'viewer', ({ query }) => {
    const where = query.state === 'all' ? '1=1' : query.state === 'overdue' ? 'c.in_at IS NULL AND c.due_at IS NOT NULL AND c.due_at < ?'
      : query.state === 'pending' ? "c.in_at IS NULL AND c.accept_status='pending'" : 'c.in_at IS NULL';
    const p = query.state === 'overdue' ? [today()] : [];
    return db.all(`SELECT c.*, a.name AS asset_name, a.asset_tag, a.type, p.name AS person, p.email, l.name AS location
      FROM asset_checkouts c JOIN assets a ON a.id=c.asset_id LEFT JOIN people p ON p.id=c.person_id LEFT JOIN locations l ON l.id=c.location_id WHERE ${where}
      ORDER BY (c.in_at IS NULL) DESC, c.due_at IS NULL, c.due_at, c.id DESC LIMIT 1000`, ...p)
      .map((c) => ({ ...c, overdue: !c.in_at && c.due_at && c.due_at < today() }));
  });

  // ======================= PHYSICAL AUDIT =======================
  const nextAuditDate = () => {
    const m = Math.max(1, Number(db.setting('audit_interval_months', 12)) || 12);
    const d = new Date(); d.setMonth(d.getMonth() + m); return d.toISOString().slice(0, 10);
  };
  function doAudit(a, body, user) {
    const next = /^\d{4}-\d\d-\d\d$/.test(body.next_audit_date || '') ? body.next_audit_date : nextAuditDate();
    const upd = { last_audit_at: nowIso(), next_audit_date: next, updated_at: nowIso() };
    if (body.location_id) upd.location_id = Number(body.location_id);
    db.update('assets', a.id, upd);
    addHistory(db, a.id, 'audit', 'audited', null, `Physically audited${body.location_id ? ` at ${db.get('SELECT name FROM locations WHERE id=?', body.location_id)?.name}` : ''}${body.notes ? ` — ${body.notes}` : ''} · next ${next}`, user.username);
  }
  r('POST', '/api/assets/:id/audit', 'tech', ({ params, body, user }) => {
    const a = mustGet('assets', params.id);
    db.tx(() => doAudit(a, body, user));
    audit(user, 'physical_audit', 'asset', a.id, a.name);
    scheduleAlerts();
    return { ok: true };
  });
  r('POST', '/api/assets/bulk-audit', 'tech', ({ body, user }) => {
    const ids = (body.ids || []).map(Number).filter(Boolean);
    db.tx(() => ids.forEach((id) => doAudit(mustGet('assets', id), body, user)));
    audit(user, 'physical_audit', 'asset', ids.join(','), `${ids.length} assets`);
    scheduleAlerts();
    return { ok: true, count: ids.length };
  });

  // ======================= STOCK: accessories, consumables, components =======================
  const STOCK_FIELDS = ['kind', 'name', 'category', 'manufacturer', 'model_number', 'location_id', 'supplier', 'qty_total', 'min_qty', 'unit_cost', 'notes'];
  const stockRow = `SELECT s.*, l.name AS location,
      COALESCE((SELECT SUM(qty) FROM stock_moves WHERE item_id=s.id AND action='checkout' AND returned=0),0) AS checked_out
      FROM stock_items s LEFT JOIN locations l ON l.id=s.location_id`;
  const withAvail = (s) => ({ ...s, available: s.qty_total - s.checked_out, low: s.min_qty > 0 && s.qty_total - s.checked_out <= s.min_qty });
  const stockIn = (body) => {
    const rec = pick(body, STOCK_FIELDS.filter((f) => !['qty_total', 'min_qty', 'unit_cost'].includes(f)));
    for (const f of ['qty_total', 'min_qty']) if (f in body && body[f] !== '' && body[f] !== null) { const n = Number(body[f]); if (!Number.isInteger(n) || n < 0) throw bad(`${f.replace('_', ' ')} must be a whole number ≥ 0`); rec[f] = n; }
    if ('unit_cost' in body) rec.unit_cost = body.unit_cost === '' || body.unit_cost === null ? null : Number(body.unit_cost);
    if (rec.kind && !['accessory', 'consumable', 'component'].includes(rec.kind)) throw bad('Invalid kind');
    return rec;
  };
  r('GET', '/api/stock', 'viewer', ({ query }) => {
    const where = [], p = [];
    if (query.kind) { where.push('s.kind=?'); p.push(query.kind); }
    if (query.q) { where.push('(s.name LIKE ? OR s.category LIKE ? OR s.manufacturer LIKE ? OR s.model_number LIKE ?)'); p.push(...Array(4).fill(`%${query.q}%`)); }
    let rows = db.all(`${stockRow} ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY s.name COLLATE NOCASE`, ...p).map(withAvail);
    if (query.low === '1') rows = rows.filter((s) => s.low);
    return rows;
  });
  r('GET', '/api/stock/:id', 'viewer', ({ params }) => {
    const s = db.get(`${stockRow} WHERE s.id=?`, params.id);
    if (!s) throw notFound('Item not found');
    return {
      ...withAvail(s),
      holders: db.all(`SELECT m.id, m.qty, m.ts, m.notes, m.by_user, p.id AS person_id, p.name AS person FROM stock_moves m LEFT JOIN people p ON p.id=m.person_id
        WHERE m.item_id=? AND m.action='checkout' AND m.returned=0 ORDER BY m.ts DESC`, s.id),
      moves: db.all(`SELECT m.*, p.name AS person FROM stock_moves m LEFT JOIN people p ON p.id=m.person_id WHERE m.item_id=? ORDER BY m.id DESC LIMIT 300`, s.id),
    };
  });
  r('POST', '/api/stock', 'tech', ({ body, user }) => {
    const rec = stockIn(body);
    if (!rec.name) throw bad('Name is required');
    const id = db.insert('stock_items', rec);
    if (rec.qty_total) db.insert('stock_moves', { item_id: id, action: 'restock', qty: rec.qty_total, by_user: user.username, notes: 'Initial quantity' });
    audit(user, 'create', 'stock', id, rec.name); scheduleAlerts();
    return { id };
  });
  r('PUT', '/api/stock/:id', 'tech', ({ params, body, user }) => {
    const s = mustGet('stock_items', params.id);
    const rec = stockIn(body);
    db.tx(() => {
      if ('qty_total' in rec && rec.qty_total !== s.qty_total) db.insert('stock_moves', { item_id: s.id, action: 'adjust', qty: rec.qty_total - s.qty_total, by_user: user.username, notes: 'Quantity corrected' });
      db.update('stock_items', s.id, rec);
    });
    audit(user, 'update', 'stock', s.id); scheduleAlerts();
    return { ok: true };
  });
  r('DELETE', '/api/stock/:id', 'tech', ({ params, user }) => { db.run('DELETE FROM stock_items WHERE id=?', params.id); audit(user, 'delete', 'stock', params.id); return { ok: true }; });
  r('POST', '/api/stock/:id/checkout', 'tech', ({ params, body, user }) => {
    const s = withAvail(db.get(`${stockRow} WHERE s.id=?`, params.id) || (() => { throw notFound('Item not found'); })());
    const qty = Number(body.qty) || 1;
    if (!Number.isInteger(qty) || qty < 1) throw bad('Quantity must be a whole number ≥ 1');
    if (qty > s.available) throw bad(`Only ${s.available} available`);
    const p = mustGet('people', body.person_id);
    db.tx(() => {
      if (s.kind === 'consumable') {  // consumables are used up, not returned
        db.insert('stock_moves', { item_id: s.id, action: 'consume', qty, person_id: p.id, by_user: user.username, notes: body.notes || null });
        db.run('UPDATE stock_items SET qty_total=qty_total-? WHERE id=?', qty, s.id);
      } else db.insert('stock_moves', { item_id: s.id, action: 'checkout', qty, person_id: p.id, by_user: user.username, notes: body.notes || null });
    });
    audit(user, s.kind === 'consumable' ? 'consume' : 'checkout', 'stock', s.id, `${qty} × ${s.name} -> ${p.name}`); scheduleAlerts();
    return { ok: true };
  });
  r('POST', '/api/stock/:id/checkin', 'tech', ({ params, body, user }) => {
    const m = db.get("SELECT * FROM stock_moves WHERE id=? AND item_id=? AND action='checkout' AND returned=0", body.move_id, params.id);
    if (!m) throw bad('That check-out was not found or is already returned');
    db.tx(() => {
      db.run('UPDATE stock_moves SET returned=1 WHERE id=?', m.id);
      db.insert('stock_moves', { item_id: m.item_id, action: 'checkin', qty: m.qty, person_id: m.person_id, by_user: user.username, notes: body.notes || null });
    });
    audit(user, 'checkin', 'stock', params.id, `${m.qty} returned`); scheduleAlerts();
    return { ok: true };
  });
  r('POST', '/api/stock/:id/restock', 'tech', ({ params, body, user }) => {
    const s = mustGet('stock_items', params.id);
    const qty = Number(body.qty);
    if (!Number.isInteger(qty) || qty === 0) throw bad('Enter a non-zero whole number (negative to write off)');
    if (s.qty_total + qty < 0) throw bad('Quantity cannot go below zero');
    db.tx(() => {
      db.insert('stock_moves', { item_id: s.id, action: qty > 0 ? 'restock' : 'writeoff', qty, by_user: user.username, notes: body.notes || null });
      db.run('UPDATE stock_items SET qty_total=qty_total+? WHERE id=?', qty, s.id);
    });
    audit(user, qty > 0 ? 'restock' : 'writeoff', 'stock', s.id, `${qty}`); scheduleAlerts();
    return { ok: true };
  });

  // ======================= PERMISSION GROUPS (admin) =======================
  r('GET', '/api/groups', 'admin', () => ({
    catalog: PERM_CATALOG,
    groups: db.all('SELECT g.*, (SELECT COUNT(*) FROM users WHERE group_id=g.id) AS members FROM perm_groups g ORDER BY name')
      .map((g) => ({ ...g, perms: JSON.parse(g.perms || '[]') })),
    role_defaults: { viewer: roleDefaults('viewer'), tech: roleDefaults('tech') },
  }));
  const groupIn = (body) => {
    const name = String(body.name || '').trim().slice(0, 80);
    if (!name) throw bad('Name is required');
    const perms = (Array.isArray(body.perms) ? body.perms : []).filter((p) => ALL_PERMS.includes(p) && p !== 'admin.all');
    return { name, description: String(body.description || '').slice(0, 300) || null, perms: JSON.stringify([...new Set(perms)]) };
  };
  r('POST', '/api/groups', 'admin', ({ body, user }) => {
    const rec = groupIn(body);
    if (db.get('SELECT id FROM perm_groups WHERE name=? COLLATE NOCASE', rec.name)) throw bad('A group with this name exists');
    const id = db.insert('perm_groups', rec); audit(user, 'create', 'group', id, rec.name);
    return { id };
  });
  r('PUT', '/api/groups/:id', 'admin', ({ params, body, user }) => { mustGet('perm_groups', params.id); db.update('perm_groups', params.id, groupIn(body)); audit(user, 'update', 'group', params.id, body.perms?.join(',')); return { ok: true }; });
  r('DELETE', '/api/groups/:id', 'admin', ({ params, user }) => { db.run('DELETE FROM perm_groups WHERE id=?', params.id); audit(user, 'delete', 'group', params.id); return { ok: true }; });

  // ======================= SELF-SERVICE (end-user login) =======================
  r('POST', '/api/people/:id/login', 'admin', ({ params, body, user }) => {
    const p = mustGet('people', params.id);
    if (db.get('SELECT id FROM users WHERE person_id=?', p.id)) throw bad('This person already has a login');
    const username = String(body.username || p.email || '').trim();
    if (!username) throw bad('Username is required');
    if (db.get('SELECT id FROM users WHERE username=?', username)) throw bad('Username already exists');
    const problem = passwordProblem(body.password, username);
    if (problem) throw bad(problem);
    const id = db.insert('users', { username, name: p.name, email: p.email, role: 'user', person_id: p.id, pass_hash: hashPassword(body.password), must_change: 1, password_changed_at: nowIso() });
    audit(user, 'create', 'user', id, `self-service login for ${p.name}`);
    return { id };
  });
  const selfPerson = (user) => {
    if (!user.person_id) throw bad('Your account is not linked to a person record — ask IT to link it.');
    return mustGet('people', user.person_id);
  };
  r('GET', '/api/self', 'user', ({ user }) => {
    if (!user.person_id) return { person: null, assets: [], pending: [], stock: [], eula: db.setting('eula_text', '') };
    const p = selfPerson(user);
    return {
      person: { id: p.id, name: p.name, email: p.email, title: p.title },
      eula: db.setting('eula_text', ''),
      assets: db.all(`SELECT a.id, a.asset_tag, a.name, a.type, a.manufacturer, a.model, a.serial, a.status, a.warranty_end,
          c.id AS checkout_id, c.out_at, c.due_at, c.accept_status, c.accept_at FROM assets a
        LEFT JOIN asset_checkouts c ON c.asset_id=a.id AND c.in_at IS NULL WHERE a.person_id=? ORDER BY a.name`, p.id),
      stock: db.all(`SELECT m.id, m.qty, m.ts, s.name, s.kind, s.model_number FROM stock_moves m JOIN stock_items s ON s.id=m.item_id
        WHERE m.person_id=? AND m.action='checkout' AND m.returned=0 ORDER BY m.ts DESC`, p.id),
      history: db.all(`SELECT c.out_at, c.in_at, c.accept_status, a.name, a.asset_tag FROM asset_checkouts c JOIN assets a ON a.id=c.asset_id
        WHERE c.person_id=? ORDER BY c.id DESC LIMIT 50`, p.id),
    };
  });
  r('POST', '/api/self/checkouts/:id/:decision', 'user', ({ params, body, user }) => {
    const p = selfPerson(user);
    if (!['accept', 'decline'].includes(params.decision)) throw bad('Invalid decision');
    const c = db.get("SELECT c.*, a.name AS asset_name FROM asset_checkouts c JOIN assets a ON a.id=c.asset_id WHERE c.id=? AND c.person_id=? AND c.in_at IS NULL", params.id, p.id);
    if (!c) throw notFound('Assignment not found');
    if (c.accept_status !== 'pending') throw bad('This assignment has already been answered');
    if (params.decision === 'accept' && String(body.signature || '').trim().toLowerCase() !== String(p.name).trim().toLowerCase()) {
      throw bad(`Type your full name exactly as "${p.name}" to sign`);
    }
    const status = params.decision === 'accept' ? 'accepted' : 'declined';
    db.tx(() => {
      db.run('UPDATE asset_checkouts SET accept_status=?, accept_at=?, accept_note=?, accept_name=? WHERE id=?', status, nowIso(), String(body.note || '').slice(0, 1000) || null, body.signature || null, c.id);
      addHistory(db, c.asset_id, 'assignment', status, null, `${p.name} ${status} the assignment${body.note ? ` — ${body.note}` : ''}`, user.username);
    });
    audit(user, `assignment_${status}`, 'asset', c.asset_id, c.asset_name);
    scheduleAlerts();
    return { ok: true };
  });

  // ======================= IMPORT CENTRE (stored files, mapping, dry run) =======================
  const importDir = path.join(dataDir, 'imports');
  fs.mkdirSync(importDir, { recursive: true });
  const importCtx = { ASSET_TYPES, ASSET_STATUSES, dataDir, hashPassword, encrypt: (s) => vault.encrypt(s), decrypt: (s) => vault.decrypt(s) };
  const readImport = (f) => vault.decBytes(fs.readFileSync(path.join(importDir, f.file))).toString('utf8');
  const fileRow = (f) => { let last = null; try { last = JSON.parse(f.last_result || 'null'); } catch { /* none */ } return { id: f.id, name: f.name, size: f.size, rows: f.rows, created_at: f.created_at, created_by: f.created_by, last_type: f.last_type, last_run_at: f.last_run_at, last_result: last }; };
  r('GET', '/api/import/types', 'tech', () => IMPORT_TYPES);
  r('GET', '/api/import/files', 'tech', () => db.all('SELECT * FROM import_files ORDER BY id DESC LIMIT 200').map(fileRow));
  r('POST', '/api/import/files', 'tech', ({ body, user }) => {
    const name = String(body.name || 'import.csv').replace(/[^\w.\- ()]/g, '_').slice(0, 120);
    const csv = String(body.csv || '');
    if (!csv.trim()) throw bad('The file is empty');
    if (csv.length > 25 * 1024 * 1024) throw bad('File too large (max 25 MB)');
    let rows;
    try { rows = readRows(csv).length; } catch (e) { throw bad(`Could not read CSV: ${e.message}`); }
    if (!rows) throw bad('No data rows found — the first row must contain the column names');
    const file = `${Date.now()}-${crypto.randomBytes(4).toString('hex')}.enc`;
    fs.writeFileSync(path.join(importDir, file), vault.encBytes(Buffer.from(csv, 'utf8')));   // CSVs often hold personal data: encrypted at rest
    const id = db.insert('import_files', { name, size: Buffer.byteLength(csv), rows, file, created_by: user.username });
    audit(user, 'upload', 'import_file', id, `${name} (${rows} rows)`);
    return { id };
  });
  r('DELETE', '/api/import/files/:id', 'tech', ({ params, user }) => {
    const f = mustGet('import_files', params.id);
    fs.rmSync(path.join(importDir, f.file), { force: true });
    db.run('DELETE FROM import_files WHERE id=?', f.id);
    audit(user, 'delete', 'import_file', f.id, f.name);
    return { ok: true };
  });
  r('GET', '/api/import/files/:id/analyse', 'tech', ({ params, query }) => {
    const f = mustGet('import_files', params.id);
    const type = IMPORT_TYPES[query.type] ? query.type : (f.last_type || 'assets');
    let prev = null;
    try { prev = f.last_type === type ? JSON.parse(f.last_mapping || 'null') : null; } catch { /* none */ }
    try { return { type, file: fileRow(f), ...analyse(readImport(f), type, db, prev) }; } catch (e) { throw bad(e.message); }
  });
  r('POST', '/api/import/files/:id/run', 'tech', ({ params, body, user }) => {
    const f = mustGet('import_files', params.id);
    if (!IMPORT_TYPES[body.type]) throw bad('Choose what you are importing');
    let out;
    try { out = runImport(db, { ...body, csv: readImport(f) }, user, importCtx); } catch (e) { throw bad(e.message); }
    db.update('import_files', f.id, { last_mapping: JSON.stringify(body.mapping || {}), last_type: body.type,
      ...(out.dry_run ? {} : { last_run_at: nowIso(), last_result: JSON.stringify({ created: out.created, updated: out.updated, errors: out.error_count, type: body.type }) }) });
    if (!out.dry_run) {
      audit(user, 'import', body.type, f.id, `${f.name}: ${out.created} created, ${out.updated} updated, ${out.checked_out} checked out, ${out.error_count} errors${out.backup ? `, backup ${out.backup}` : ''}`);
      scheduleAlerts();
    }
    return out;
  });
  // Inline variants (no stored file) — used by scripts and API tokens
  r('POST', '/api/import/preview', 'tech', ({ body }) => { try { return analyse(body.csv, body.type, db); } catch (e) { throw bad(e.message); } });
  r('POST', '/api/import/run', 'tech', ({ body, user }) => {
    let out;
    try { out = runImport(db, body, user, importCtx); } catch (e) { throw bad(e.message); }
    if (!out.dry_run) { audit(user, 'import', body.type, null, `${out.created} created, ${out.updated} updated, ${out.error_count} errors`); scheduleAlerts(); }
    return out;
  });

  // ======================= CATALOG: companies, manufacturers, suppliers, categories, models =======================
  const catalogCrud = (base, table, fields, listSql) => {
    r('GET', `/api/${base}`, 'viewer', () => db.all(listSql));
    r('POST', `/api/${base}`, 'tech', ({ body, user }) => {
      const rec = pick(body, fields);
      if (!rec.name) throw bad('Name is required');
      try { const id = db.insert(table, rec); audit(user, 'create', table, id, rec.name); return { id }; }
      catch (e) { if (/UNIQUE/.test(e.message)) throw bad(`"${rec.name}" already exists`); throw e; }
    });
    r('PUT', `/api/${base}/:id`, 'tech', ({ params, body, user }) => {
      mustGet(table, params.id);
      try { db.update(table, params.id, pick(body, fields)); } catch (e) { if (/UNIQUE/.test(e.message)) throw bad('That name already exists'); throw e; }
      if (table === 'asset_models') syncModel(Number(params.id));
      audit(user, 'update', table, params.id);
      return { ok: true };
    });
    r('DELETE', `/api/${base}/:id`, 'tech', ({ params, user }) => { db.run(`DELETE FROM ${table} WHERE id=?`, params.id); audit(user, 'delete', table, params.id); return { ok: true }; });
  };
  /** Keep assets' denormalised manufacturer/model text in step with their model record. */
  function syncModel(modelId) {
    const m = db.get('SELECT am.name, am.model_number, mf.name AS mfr FROM asset_models am LEFT JOIN manufacturers mf ON mf.id=am.manufacturer_id WHERE am.id=?', modelId);
    if (m) db.run('UPDATE assets SET model=?, manufacturer=COALESCE(?, manufacturer) WHERE model_id=?', [m.name, m.model_number && m.model_number !== m.name ? m.model_number : null].filter(Boolean).join(' '), m.mfr, modelId);
  }
  catalogCrud('companies', 'companies', ['name', 'phone', 'email', 'notes'],
    `SELECT c.*, (SELECT COUNT(*) FROM assets WHERE company_id=c.id) AS assets, (SELECT COUNT(*) FROM people WHERE company_id=c.id) AS people FROM companies c ORDER BY name`);
  catalogCrud('manufacturers', 'manufacturers', ['name', 'url', 'support_url', 'support_email', 'support_phone', 'notes'],
    `SELECT m.*, (SELECT COUNT(*) FROM asset_models WHERE manufacturer_id=m.id) AS models, (SELECT COUNT(*) FROM assets WHERE manufacturer=m.name COLLATE NOCASE) AS assets FROM manufacturers m ORDER BY name`);
  catalogCrud('suppliers', 'suppliers', ['name', 'contact', 'email', 'phone', 'address', 'url', 'notes'],
    `SELECT s.*, (SELECT COUNT(*) FROM assets WHERE supplier_id=s.id) AS assets FROM suppliers s ORDER BY name`);
  catalogCrud('categories', 'categories', ['name', 'kind', 'notes'],
    `SELECT c.*, (SELECT COUNT(*) FROM asset_models WHERE category_id=c.id) AS models,
      (SELECT COUNT(*) FROM assets a JOIN asset_models am ON am.id=a.model_id WHERE am.category_id=c.id) AS assets,
      (SELECT COUNT(*) FROM stock_items WHERE category=c.name COLLATE NOCASE) AS items FROM categories c ORDER BY kind, name`);
  catalogCrud('models', 'asset_models', ['name', 'model_number', 'manufacturer_id', 'category_id', 'asset_type', 'eol_months', 'notes'],
    `SELECT am.*, mf.name AS manufacturer, c.name AS category, (SELECT COUNT(*) FROM assets WHERE model_id=am.id) AS assets
      FROM asset_models am LEFT JOIN manufacturers mf ON mf.id=am.manufacturer_id LEFT JOIN categories c ON c.id=am.category_id ORDER BY mf.name, am.name`);

  // ======================= MAP =======================
  r('GET', '/api/map', 'viewer', () => ({
    locations: db.all(`SELECT l.id, l.name, l.address, l.lat, l.lng,
        (SELECT COUNT(*) FROM assets WHERE location_id=l.id) AS assets,
        (SELECT COUNT(*) FROM assets WHERE location_id=l.id AND status='in_use') AS in_use,
        (SELECT COUNT(*) FROM assets WHERE location_id=l.id AND status='in_stock') AS in_stock,
        (SELECT COUNT(*) FROM people WHERE location_id=l.id) AS people,
        (SELECT COALESCE(SUM(qty_total),0) FROM stock_items WHERE location_id=l.id) AS stock
      FROM locations l ORDER BY l.name`),
    unassigned: db.get('SELECT COUNT(*) AS n FROM assets WHERE location_id IS NULL').n,
  }));
  r('PUT', '/api/locations/:id/position', 'tech', ({ params, body, user }) => {
    mustGet('locations', params.id);
    const lat = body.lat === null ? null : Number(body.lat), lng = body.lng === null ? null : Number(body.lng);
    if (lat !== null && (!(lat >= -90 && lat <= 90) || !(lng >= -180 && lng <= 180))) throw bad('Invalid coordinates');
    db.run('UPDATE locations SET lat=?, lng=? WHERE id=?', lat, lng, params.id);
    audit(user, 'update', 'locations', params.id, 'map position');
    return { ok: true };
  });

  // ======================= SECURITY CENTER (admin) =======================
  const SEC_KEYS = ['portal_ip_allowlist', 'password_max_age_days', 'require_2fa_admins', 'session_idle_min', 'session_max_hours',
    'uninstall_protection', 'webhook_kind', 'webhook_min_severity'];
  r('GET', '/api/security', 'admin', ({ ip }) => {
    const users = db.all('SELECT role, totp_enabled FROM users');
    let last = null;
    try { last = JSON.parse(db.setting('webhook_last', 'null')); } catch { /* none */ }
    const webhook = vault.decrypt(db.setting('webhook_url_enc', '')) || '';
    return {
      settings: Object.fromEntries(SEC_KEYS.map((k) => [k, db.setting(k, '')])),
      your_ip: ip,
      webhook_url_masked: webhook ? webhook.replace(/^(https?:\/\/[^/]+\/).*$/, '$1…') : '',
      webhook_secret_set: !!db.setting('webhook_secret_enc', ''),
      webhook_last: last,
      uninstall_code: vault.decrypt(db.setting('uninstall_code_enc', '')) || null,
      audit: auditVerify(db),
      posture: {
        https: false, // filled by client from location.protocol
        admins: users.filter((u) => u.role === 'admin').length,
        admins_without_2fa: users.filter((u) => u.role === 'admin' && !u.totp_enabled).length,
        users_with_2fa: users.filter((u) => u.totp_enabled).length, users: users.length,
        active_sessions: db.get('SELECT COUNT(*) AS n FROM sessions WHERE expires_at > ?', Date.now()).n,
        tokens: db.get('SELECT COUNT(*) AS n FROM api_tokens WHERE revoked=0').n,
        failed_logins_24h: db.get("SELECT COUNT(*) AS n FROM audit_log WHERE action LIKE 'login_failed%' AND ts >= ?", new Date(Date.now() - 86400000).toISOString()).n,
        master_key_env: !!process.env.MASTER_KEY,
      },
    };
  });
  r('PUT', '/api/security', 'admin', ({ body, user, ip }) => {
    if ('portal_ip_allowlist' in body) {
      let rules;
      try { rules = parseAllowlist(body.portal_ip_allowlist); } catch (e) { throw bad(e.message); }
      if (!ipAllowed(ip, rules)) throw bad(`Your current address (${ip}) is not in the list — saving would lock you out.`);
    }
    if ('webhook_url' in body) {
      const u = String(body.webhook_url || '').trim();
      if (u && !/^https?:\/\/[^\s]+$/i.test(u)) throw bad('Webhook URL must start with http:// or https://');
      db.setSetting('webhook_url_enc', u ? vault.encrypt(u) : '');
    }
    if ('webhook_secret' in body && body.webhook_secret !== undefined) db.setSetting('webhook_secret_enc', body.webhook_secret ? vault.encrypt(String(body.webhook_secret)) : '');
    for (const k of SEC_KEYS) if (k in body) db.setSetting(k, body[k] ?? '');
    if (body.uninstall_protection === '1' && !db.setting('uninstall_code_enc')) {
      db.setSetting('uninstall_code_enc', vault.encrypt(String(crypto.randomInt(10000000, 99999999))));
    }
    audit(user, 'update', 'security', null, Object.keys(body).filter((k) => !/secret|url/.test(k)).join(','));
    return { ok: true };
  });
  r('POST', '/api/security/uninstall-code', 'admin', ({ user }) => {
    db.setSetting('uninstall_code_enc', vault.encrypt(String(crypto.randomInt(10000000, 99999999))));
    audit(user, 'rotate', 'uninstall_code', null);
    return { ok: true };
  });
  r('POST', '/api/security/webhook-test', 'admin', async ({ user }) => {
    const out = await sendWebhook(db, vault, [{ id: 0, kind: 'test', severity: 'critical', message: `Test notification sent by ${user.username}`, asset_id: null }]);
    if (!out.sent) throw bad(out.error ? `Webhook failed: ${out.error}` : out.status ? `Webhook returned HTTP ${out.status}` : 'No webhook URL configured');
    return out;
  });

  // API tokens (for integrations / BI / SIEM). Shown once; stored as SHA-256 hashes.
  r('GET', '/api/tokens', 'admin', () => db.all('SELECT id, name, prefix, role, created_by, created_at, expires_at, last_used_at, last_ip, revoked FROM api_tokens ORDER BY revoked, id DESC'));
  r('POST', '/api/tokens', 'admin', ({ body, user }) => {
    const name = String(body.name || '').trim().slice(0, 80);
    if (!name) throw bad('Name is required');
    if (!['viewer', 'tech'].includes(body.role)) throw bad('Role must be viewer or tech');
    const days = Number(body.days) || 0;
    if (days < 0 || days > 730) throw bad('Expiry must be 0–730 days');
    const out = createToken(db, { name, role: body.role, days, by: user.username });
    audit(user, 'create', 'api_token', out.id, `${name} (${body.role})`);
    return out;
  });
  r('DELETE', '/api/tokens/:id', 'admin', ({ params, user }) => {
    db.run('UPDATE api_tokens SET revoked=1 WHERE id=?', params.id);
    audit(user, 'revoke', 'api_token', params.id);
    return { ok: true };
  });

  // Audit integrity + export
  r('GET', '/api/audit/verify', 'admin', ({ user }) => { const v = auditVerify(db); audit(user, 'verify', 'audit_log', null, v.ok ? `ok (${v.checked})` : `BROKEN at ${v.broken_at}`); return v; });
  r('GET', '/api/audit/export', 'admin', ({ res, user }) => {
    audit(user, 'export', 'audit_log', null);
    const rows = db.all('SELECT id, ts, username, ip, action, entity, entity_id, detail, prev_hash, hash FROM audit_log ORDER BY id');
    send(res, 200, toCsv(['id', 'ts', 'username', 'ip', 'action', 'entity', 'entity_id', 'detail', 'prev_hash', 'hash'].map((k) => ({ key: k })), rows),
      { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': `attachment; filename="audit-${today()}.csv"` });
  });

  // Encrypted backup (database + master key, protected by an admin passphrase)
  r('POST', '/api/admin/backup', 'admin', ({ body, res, user }) => {
    const pass = String(body.passphrase || '');
    if (pass.length < 12) throw bad('Passphrase must be at least 12 characters');
    const buf = createBackup(db, dataDir, pass);
    audit(user, 'backup', 'database', null, `${(buf.length / 1048576).toFixed(1)} MB`);
    send(res, 200, buf, { 'Content-Type': 'application/octet-stream', 'Content-Disposition': `attachment; filename="asset-portal-${today()}.apbak"`, 'Cache-Control': 'no-store' });
  });

  // ======================= DOWNLOADS =======================
  // Pre-configured token: portal URL + enrollment key + pin of the server's encryption key.
  const setupToken = (origin) => {
    const server = String(db.setting('public_url') || origin).replace(/\/+$/, '');
    const pin = crypto.createHash('sha256').update(vault.serverPub).digest().subarray(0, 16).toString('base64url');
    return { server, pin, token: Buffer.from(JSON.stringify({ s: server, k: db.setting('enrollment_key'), p: pin })).toString('base64url') };
  };
  const checkKey = (k) => { if (!k || k !== db.setting('enrollment_key')) throw new HttpError(403, 'Invalid enrollment key'); };
  r('GET', `/download/${SETUP_EXE}`, 'public', ({ res }) => serveFile(res, path.join(downloadDir, SETUP_EXE), {
    'Content-Disposition': `attachment; filename="${SETUP_EXE}"`, 'Cache-Control': 'no-cache',
  }));
  // The configuration rides in the file name, so double-clicking installs with no typing and the server key is pinned.
  r('GET', '/download/setup', 'public', ({ query, res, origin }) => {
    checkKey(query.key);
    serveFile(res, path.join(downloadDir, SETUP_EXE), {
      'Content-Disposition': `attachment; filename="AssetAgentSetup-${setupToken(origin).token}.exe"`, 'Cache-Control': 'no-store',
    });
  });
  r('GET', '/download/install.ps1', 'public', ({ query, res, origin }) => {
    checkKey(query.key);
    const { server, pin } = setupToken(origin);
    const safe = (s) => String(s).replace(/[^A-Za-z0-9.:\-\[\]\/_]/g, '');
    const script = `# Asset Inventory Agent - unattended install. Run from an elevated PowerShell.
$ErrorActionPreference = 'Stop'
$server = '${safe(server)}'
$key = '${safe(db.setting('enrollment_key'))}'
$pin = '${safe(pin)}'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Please run this from an elevated (Administrator) PowerShell.' }
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$tmp = Join-Path $env:TEMP ('AssetAgentSetup-' + [guid]::NewGuid().ToString('N') + '.exe')
Write-Host "Downloading Asset Inventory Agent from $server ..."
Invoke-WebRequest -UseBasicParsing -Uri "$server/download/${SETUP_EXE}" -OutFile $tmp
$p = Start-Process -FilePath $tmp -ArgumentList @('/quiet', '--server', $server, '--key', $key, '--pin', $pin) -Wait -PassThru
Remove-Item $tmp -Force -ErrorAction SilentlyContinue
if ($p.ExitCode -ne 0) { throw "Install failed (exit code $($p.ExitCode)). See C:\\ProgramData\\AssetAgent\\logs\\setup.log" }
Write-Host 'Asset Inventory Agent installed and reporting.'
`;
    send(res, 200, script, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
  });

  return { router, ROLES, audit };
}