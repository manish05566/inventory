import crypto from 'node:crypto';

export const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
export const nowIso = () => new Date().toISOString();
export const today = () => new Date().toISOString().slice(0, 10);
const addDays = (d) => new Date(Date.now() + d * 86400000).toISOString().slice(0, 10);

const GENERIC_SERIALS = new Set([
  '', '0', '00000000', '0000000000', '123456789', 'none', 'n/a', 'na', 'default string', 'to be filled by o.e.m.',
  'system serial number', 'not specified', 'not applicable', 'chassis serial number', 'oem', 'invalid',
]);
const goodSerial = (s) => s && !GENERIC_SERIALS.has(String(s).trim().toLowerCase()) && !/^0+$/.test(String(s).trim());
const goodUuid = (u) => u && !/^[0-]+$/.test(u) && !/^[f-]+$/i.test(u) && !/^03000200-0400-0500-0006-000700080009$/i.test(u);

const list = (v) => (Array.isArray(v) ? v : v ? [v] : []);
const str = (v, max = 500) => (v === null || v === undefined || v === '' ? null : String(v).slice(0, max));
const num = (v) => (v === null || v === undefined || v === '' || isNaN(Number(v)) ? null : Number(v));

export function assetTag(db, id) {
  return `${db.setting('asset_tag_prefix', 'AST-')}${String(id).padStart(5, '0')}`;
}

export function addHistory(db, assetId, kind, field, oldV, newV, actor = 'agent') {
  db.run('INSERT INTO asset_history(asset_id,kind,field,old_value,new_value,actor) VALUES(?,?,?,?,?,?)',
    assetId, kind, field, str(oldV, 2000), str(newV, 2000), actor);
}

function guessType(p) {
  const os = (p.os?.name || '').toLowerCase();
  const chassis = p.system?.chassis;
  if (chassis === 'vm') return 'virtual_machine';
  if (os.includes('server')) return 'server';
  if (chassis === 'laptop') return 'laptop';
  return 'workstation';
}

/** Find an existing asset that matches this machine so re-installs / manual records are merged. */
function matchAsset(db, sys, macs) {
  if (goodUuid(sys.uuid)) {
    const a = db.get('SELECT id FROM assets WHERE hw_uuid=? ORDER BY id LIMIT 1', sys.uuid);
    if (a) return a.id;
  }
  if (goodSerial(sys.serial)) {
    const a = db.get("SELECT id FROM assets WHERE serial=? AND status NOT IN ('disposed') ORDER BY id LIMIT 1", sys.serial);
    if (a) return a.id;
  }
  if (sys.hostname) {
    for (const mac of macs) {
      const a = db.get('SELECT id FROM assets WHERE hostname=? COLLATE NOCASE AND mac=? LIMIT 1', sys.hostname, mac);
      if (a) return a.id;
    }
  }
  return null;
}

export function enroll(db, vault, body, ip) {
  const key = db.setting('enrollment_key');
  if (!body.key || !key || !crypto.timingSafeEqual(Buffer.from(sha256(String(body.key))), Buffer.from(sha256(key)))) {
    return null;
  }
  const sys = body.system || {};
  const macs = list(body.macs).map((m) => String(m).toUpperCase());
  return db.tx(() => {
    let assetId = matchAsset(db, sys, macs);
    if (assetId) {
      db.run('DELETE FROM agents WHERE asset_id=?', assetId);
      db.run("UPDATE assets SET source=CASE WHEN source='manual' OR source='discovery' THEN 'agent' ELSE source END WHERE id=?", assetId);
      addHistory(db, assetId, 'agent', 'agent', null, 'Agent enrolled (matched existing asset)');
    } else {
      assetId = db.insert('assets', {
        name: str(sys.hostname) || 'Unknown device', hostname: str(sys.hostname), type: guessType(body),
        source: 'agent', status: 'in_use', serial: str(sys.serial), hw_uuid: str(sys.uuid),
      });
      db.run('UPDATE assets SET asset_tag=? WHERE id=?', assetTag(db, assetId), assetId);
      addHistory(db, assetId, 'created', null, null, 'Created by agent enrollment');
    }
    const agentId = crypto.randomUUID();
    const secret = crypto.randomBytes(32).toString('base64');
    db.insert('agents', { id: agentId, asset_id: assetId, token_hash: '', secret_enc: vault.encrypt(secret), version: str(body.agent_version), last_ip: ip });
    return { agent_id: agentId, secret, asset_id: assetId, interval_min: Number(db.setting('agent_interval_min', 60)) };
  });
}

const TRACKED = [
  ['hostname', 'hardware'], ['domain', 'hardware'], ['manufacturer', 'hardware'], ['model', 'hardware'],
  ['serial', 'hardware'], ['cpu', 'hardware'], ['cpu_cores', 'hardware'], ['ram_mb', 'hardware'],
  ['disk_total_gb', 'hardware'], ['os_name', 'os'], ['os_version', 'os'], ['os_build', 'os'],
  ['ip', 'network'], ['mac', 'network'], ['last_user', 'user'], ['antivirus', 'security'], ['encryption', 'security'],
];

export function checkin(db, agent, p, ip) {
  const sys = p.system || {}, os = p.os || {}, cpu = p.cpu || {};
  const disks = list(p.disks), nics = list(p.nics);
  const primaryNic = nics.find((n) => n.gateway) || nics[0] || {};
  const ipList = list(primaryNic.ip).filter((x) => /^\d+\.\d+\.\d+\.\d+$/.test(x));
  const av = list(p.antivirus).map((a) => a.name + (a.state ? ` (${a.state})` : '')).join(', ');
  const enc = list(p.encryption).map((e) => `${e.drive} ${e.status}`).join(', ');
  const round = (x) => (x === null ? null : Math.round(x * 10) / 10);

  const fields = {
    hostname: str(sys.hostname), domain: str(sys.domain), manufacturer: str(sys.manufacturer), model: str(sys.model),
    serial: str(sys.serial), hw_uuid: str(sys.uuid),
    os_name: str(os.name), os_version: str(os.version), os_build: str(os.build), os_arch: str(os.arch),
    cpu: str(cpu.name), cpu_cores: num(cpu.cores), ram_mb: num(sys.ram_mb),
    disk_total_gb: round(disks.reduce((s, d) => s + (num(d.size_gb) || 0), 0)),
    disk_free_gb: round(disks.reduce((s, d) => s + (num(d.free_gb) || 0), 0)),
    ip: ipList[0] || null, mac: str(primaryNic.mac), last_user: str(sys.logged_user), last_boot: str(os.last_boot),
    antivirus: av || null, encryption: enc || null,
    hardware_json: JSON.stringify({
      cpu, bios: p.bios || null, motherboard: p.motherboard || null, memory_modules: list(p.memory_modules),
      physical_disks: list(p.physical_disks), gpus: list(p.gpus), monitors: list(p.monitors),
      os, chassis: sys.chassis || null, uuid: sys.uuid || null, tpm: p.tpm || null,
    }),
  };

  return db.tx(() => {
    const old = db.get('SELECT * FROM assets WHERE id=?', agent.asset_id);
    if (!old) return false;
    const first = !agent.last_checkin;
    if (!first) {
      for (const [f, kind] of TRACKED) {
        const a = old[f] ?? null, b = fields[f] ?? null;
        if (String(a ?? '') !== String(b ?? '') && b !== null) addHistory(db, old.id, kind, f, a, b);
      }
    }
    const upd = { ...fields, last_seen: nowIso(), updated_at: nowIso() };
    if (old.name === old.hostname || !old.name || old.name === 'Unknown device') upd.name = fields.hostname || old.name;
    for (const k of Object.keys(upd)) if (upd[k] === null && old[k] !== null && !['ip', 'last_user', 'antivirus', 'encryption'].includes(k)) delete upd[k];
    db.update('assets', old.id, upd);

    db.run('DELETE FROM asset_disks WHERE asset_id=?', old.id);
    for (const d of disks) {
      db.insert('asset_disks', { asset_id: old.id, name: str(d.name), label: str(d.label), fs: str(d.fs), size_gb: num(d.size_gb), free_gb: num(d.free_gb) });
    }
    db.run('DELETE FROM asset_nics WHERE asset_id=?', old.id);
    for (const n of nics) {
      db.insert('asset_nics', {
        asset_id: old.id, name: str(n.name), mac: str(n.mac), ip: list(n.ip).join(', '), subnet: list(n.subnet).join(', '),
        gateway: list(n.gateway).join(', '), dns: list(n.dns).join(', '), dhcp: n.dhcp ? 1 : 0,
      });
    }
    db.run('DELETE FROM asset_updates WHERE asset_id=?', old.id);
    for (const u of list(p.updates)) {
      if (!u.id) continue;
      db.run('INSERT OR IGNORE INTO asset_updates(asset_id,hotfix_id,description,installed_on) VALUES(?,?,?,?)', old.id, str(u.id), str(u.description), str(u.installed_on));
    }

    // ---- software diff ----
    if (Array.isArray(p.software)) {
      const before = new Map();
      for (const r of db.all('SELECT s.id, s.name, x.version FROM asset_software x JOIN software s ON s.id=x.software_id WHERE x.asset_id=?', old.id)) {
        before.set(`${r.id}|${r.version}`, r);
      }
      const after = new Map();
      for (const s of p.software) {
        const name = str(s.name, 300);
        if (!name) continue;
        const publisher = str(s.publisher, 300) || '';
        db.run('INSERT OR IGNORE INTO software(name,publisher) VALUES(?,?)', name, publisher);
        const sw = db.get('SELECT id FROM software WHERE name=? AND publisher=?', name, publisher);
        const version = str(s.version, 100) || '';
        after.set(`${sw.id}|${version}`, { id: sw.id, name, version, install_date: str(s.install_date, 20) });
      }
      const beforeIds = new Map([...before.values()].map((r) => [r.id, r]));
      const afterIds = new Map([...after.values()].map((r) => [r.id, r]));
      for (const [k, r] of before) {
        if (after.has(k)) continue;
        db.run('DELETE FROM asset_software WHERE asset_id=? AND software_id=? AND version=?', old.id, r.id, r.version);
        if (!first && !afterIds.has(r.id)) addHistory(db, old.id, 'software', 'uninstalled', r.version, r.name);
      }
      for (const [k, r] of after) {
        if (before.has(k)) continue;
        db.run('INSERT OR REPLACE INTO asset_software(asset_id,software_id,version,install_date) VALUES(?,?,?,?)', old.id, r.id, r.version, r.install_date);
        if (first) continue;
        const prev = beforeIds.get(r.id);
        if (prev && !after.has(`${prev.id}|${prev.version}`)) addHistory(db, old.id, 'software', 'updated', `${r.name} ${prev.version}`, `${r.name} ${r.version}`);
        else if (!prev) addHistory(db, old.id, 'software', 'installed', null, `${r.name} ${r.version}`.trim());
      }
    }
    db.run('UPDATE agents SET last_checkin=?, last_heartbeat=?, version=?, last_ip=?, scan_requested=CASE WHEN scan_requested=1 THEN 0 ELSE scan_requested END WHERE id=?',
      nowIso(), nowIso(), str(p.agent_version), ip, agent.id);
    return true;
  });
}

// ---------------- Licenses ----------------
export function licensePatterns(match) {
  return String(match || '').split(/[;\n]/).map((s) => s.trim()).filter(Boolean).map((s) => (s.includes('%') ? s : `%${s}%`));
}

export function licenseUsage(db, lic) {
  const pats = licensePatterns(lic.software_match);
  if (!pats.length) return { used: 0, assets: [] };
  const where = pats.map(() => 's.name LIKE ?').join(' OR ');
  const rows = db.all(`SELECT DISTINCT a.id, a.name, a.asset_tag, a.last_user, p.name AS person, s.name AS software, x.version
    FROM asset_software x JOIN software s ON s.id=x.software_id JOIN assets a ON a.id=x.asset_id
    LEFT JOIN people p ON p.id=a.person_id
    WHERE (${where}) AND a.status NOT IN ('retired','disposed','lost') ORDER BY a.name`, ...pats);
  let used;
  if (lic.license_type === 'per_user') used = new Set(rows.map((r) => r.person || r.last_user || `asset:${r.id}`)).size;
  else used = new Set(rows.map((r) => r.id)).size;
  return { used, assets: rows };
}

export function licenseStatus(lic, used) {
  const t = today();
  if (lic.expiry_date && lic.expiry_date < t) return 'expired';
  if (lic.license_type === 'site' || lic.seats === null || lic.seats === undefined) return 'compliant';
  if (used > lic.seats) return 'over';
  return 'compliant';
}

// ---------------- Alerts ----------------
export function evaluateAlerts(db) {
  const s = (k, d) => Number(db.setting(k, d));
  const current = new Map();
  const put = (key, asset_id, kind, severity, message) => current.set(key, { asset_id, kind, severity, message });
  const active = "a.status NOT IN ('retired','disposed','lost')";

  const pct = s('low_disk_pct', 10);
  for (const d of db.all(`SELECT d.*, a.name AS aname FROM asset_disks d JOIN assets a ON a.id=d.asset_id
      WHERE d.size_gb > 1 AND (d.free_gb * 100.0 / d.size_gb) < ? AND ${active}`, pct)) {
    const p = (d.free_gb * 100) / d.size_gb;
    put(`lowdisk:${d.asset_id}:${d.name}`, d.asset_id, 'low_disk', p < pct / 2 ? 'critical' : 'warning',
      `${d.aname}: drive ${d.name} has ${d.free_gb.toFixed(1)} GB free (${p.toFixed(0)}%)`);
  }
  const offCut = new Date(Date.now() - s('offline_days', 7) * 86400000).toISOString();
  for (const r of db.all(`SELECT a.id, a.name, g.last_heartbeat FROM agents g JOIN assets a ON a.id=g.asset_id
      WHERE a.status='in_use' AND COALESCE(g.last_heartbeat, g.enrolled_at) < ?`, offCut)) {
    put(`offline:${r.id}`, r.id, 'agent_offline', 'warning', `${r.name}: agent has not reported since ${(r.last_heartbeat || '').slice(0, 10) || 'enrollment'}`);
  }
  for (const r of db.all(`SELECT a.id, a.name, a.warranty_end FROM assets a WHERE a.warranty_end IS NOT NULL AND a.warranty_end<>''
      AND a.warranty_end >= ? AND a.warranty_end <= ? AND ${active}`, today(), addDays(s('warranty_alert_days', 30)))) {
    put(`warranty:${r.id}:${r.warranty_end}`, r.id, 'warranty_expiring', 'info', `${r.name}: warranty expires on ${r.warranty_end}`);
  }
  for (const r of db.all(`SELECT a.id, a.name, s.id AS sid, s.name AS sname FROM asset_software x
      JOIN software s ON s.id=x.software_id JOIN assets a ON a.id=x.asset_id WHERE s.status='prohibited' AND ${active}`)) {
    put(`prohibited:${r.id}:${r.sid}`, r.id, 'prohibited_software', 'critical', `${r.name}: prohibited software installed – ${r.sname}`);
  }
  const licDays = addDays(s('license_alert_days', 30));
  for (const lic of db.all('SELECT * FROM licenses')) {
    const { used } = licenseUsage(db, lic);
    if (lic.license_type !== 'site' && lic.seats !== null && used > lic.seats) {
      put(`licover:${lic.id}`, null, 'license_over', 'critical', `License "${lic.name}": ${used} in use, only ${lic.seats} seats owned`);
    }
    if (lic.expiry_date && lic.expiry_date <= licDays) {
      put(`licexp:${lic.id}:${lic.expiry_date}`, null, 'license_expiring', lic.expiry_date < today() ? 'critical' : 'warning',
        `License "${lic.name}" ${lic.expiry_date < today() ? 'expired' : 'expires'} on ${lic.expiry_date}`);
    }
  }
  const conDays = addDays(s('contract_alert_days', 30));
  for (const c of db.all("SELECT * FROM contracts WHERE end_date IS NOT NULL AND end_date<>'' AND end_date <= ? AND end_date >= ?",
    conDays, new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10))) {
    put(`conexp:${c.id}:${c.end_date}`, null, 'contract_expiring', c.end_date < today() ? 'critical' : 'warning',
      `Contract "${c.name}" (${c.vendor || 'no vendor'}) ${c.end_date < today() ? 'expired' : 'expires'} on ${c.end_date}`);
  }

  // Overdue check-outs
  for (const c of db.all(`SELECT c.id, c.due_at, a.id AS aid, a.name, p.name AS person FROM asset_checkouts c JOIN assets a ON a.id=c.asset_id
      LEFT JOIN people p ON p.id=c.person_id WHERE c.in_at IS NULL AND c.due_at IS NOT NULL AND c.due_at <> '' AND c.due_at < ?`, today())) {
    put(`overdue:${c.id}`, c.aid, 'checkout_overdue', 'warning', `${c.name}: checked out to ${c.person || 'someone'} — was due back ${c.due_at}`);
  }

  // Low stock (accessories / consumables / components)
  for (const s0 of db.all(`SELECT s.id, s.name, s.min_qty, s.qty_total - COALESCE((SELECT SUM(qty) FROM stock_moves WHERE item_id=s.id AND action='checkout' AND returned=0),0) AS avail
      FROM stock_items s WHERE s.min_qty > 0`)) {
    if (s0.avail <= s0.min_qty) put(`lowstock:${s0.id}`, null, 'low_stock', s0.avail <= 0 ? 'critical' : 'warning', `Stock "${s0.name}": ${s0.avail} available (minimum ${s0.min_qty})`);
  }
  // Physical audits overdue
  for (const a of db.all(`SELECT a.id, a.name, a.next_audit_date FROM assets a WHERE a.next_audit_date IS NOT NULL AND a.next_audit_date <> ''
      AND a.next_audit_date < ? AND ${active}`, today())) {
    put(`auditdue:${a.id}:${a.next_audit_date}`, a.id, 'audit_overdue', 'info', `${a.name}: physical audit was due ${a.next_audit_date}`);
  }
  // Assignments declined by the recipient
  for (const c of db.all(`SELECT c.id, a.id AS aid, a.name, p.name AS person FROM asset_checkouts c JOIN assets a ON a.id=c.asset_id
      LEFT JOIN people p ON p.id=c.person_id WHERE c.in_at IS NULL AND c.accept_status='declined'`)) {
    put(`declined:${c.id}`, c.aid, 'assignment_declined', 'warning', `${c.name}: ${c.person || 'the recipient'} declined the assignment`);
  }

  const created = [];
  db.tx(() => {
    const open = db.all('SELECT id, key FROM alerts WHERE resolved_at IS NULL');
    const openKeys = new Set(open.map((a) => a.key));
    for (const a of open) if (!current.has(a.key)) db.run('UPDATE alerts SET resolved_at=? WHERE id=?', nowIso(), a.id);
    for (const [key, a] of current) {
      if (openKeys.has(key)) db.run('UPDATE alerts SET message=?, severity=? WHERE key=? AND resolved_at IS NULL', a.message, a.severity, key);
      else created.push({ id: db.insert('alerts', { key, asset_id: a.asset_id, kind: a.kind, severity: a.severity, message: a.message }), ...a });
    }
  });
  return created;
}
