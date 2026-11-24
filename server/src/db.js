import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';

const NOW = "(strftime('%Y-%m-%dT%H:%M:%fZ','now'))";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL COLLATE NOCASE, name TEXT, email TEXT,
  role TEXT NOT NULL DEFAULT 'viewer', pass_hash TEXT NOT NULL, must_change INTEGER NOT NULL DEFAULT 0,
  created_at TEXT DEFAULT ${NOW}, last_login TEXT);

CREATE TABLE IF NOT EXISTS sessions(
  token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS locations(id INTEGER PRIMARY KEY, name TEXT NOT NULL, address TEXT, notes TEXT);
CREATE TABLE IF NOT EXISTS departments(id INTEGER PRIMARY KEY, name TEXT NOT NULL, notes TEXT);
CREATE TABLE IF NOT EXISTS people(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT, phone TEXT, title TEXT, username TEXT,
  department_id INTEGER REFERENCES departments(id) ON DELETE SET NULL,
  location_id INTEGER REFERENCES locations(id) ON DELETE SET NULL, notes TEXT);

CREATE TABLE IF NOT EXISTS custom_fields(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, field_type TEXT NOT NULL DEFAULT 'text', applies_to TEXT NOT NULL DEFAULT '*');

CREATE TABLE IF NOT EXISTS assets(
  id INTEGER PRIMARY KEY, asset_tag TEXT UNIQUE, name TEXT NOT NULL,
  type TEXT NOT NULL DEFAULT 'other', status TEXT NOT NULL DEFAULT 'in_use', source TEXT NOT NULL DEFAULT 'manual',
  manufacturer TEXT, model TEXT, serial TEXT, hw_uuid TEXT, hostname TEXT, domain TEXT,
  os_name TEXT, os_version TEXT, os_build TEXT, os_arch TEXT,
  cpu TEXT, cpu_cores INTEGER, ram_mb INTEGER, disk_total_gb REAL, disk_free_gb REAL,
  ip TEXT, mac TEXT, last_user TEXT, last_boot TEXT, antivirus TEXT, encryption TEXT, hardware_json TEXT,
  location_id INTEGER REFERENCES locations(id) ON DELETE SET NULL,
  department_id INTEGER REFERENCES departments(id) ON DELETE SET NULL,
  person_id INTEGER REFERENCES people(id) ON DELETE SET NULL,
  purchase_date TEXT, purchase_cost REAL, vendor TEXT, order_number TEXT, warranty_end TEXT, eol_date TEXT,
  notes TEXT, custom_json TEXT, last_seen TEXT,
  created_at TEXT DEFAULT ${NOW}, updated_at TEXT DEFAULT ${NOW});
CREATE INDEX IF NOT EXISTS ix_assets_serial ON assets(serial);
CREATE INDEX IF NOT EXISTS ix_assets_hostname ON assets(hostname);
CREATE INDEX IF NOT EXISTS ix_assets_uuid ON assets(hw_uuid);

CREATE TABLE IF NOT EXISTS asset_disks(
  id INTEGER PRIMARY KEY, asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  name TEXT, label TEXT, fs TEXT, size_gb REAL, free_gb REAL);
CREATE INDEX IF NOT EXISTS ix_disks_asset ON asset_disks(asset_id);

CREATE TABLE IF NOT EXISTS asset_nics(
  id INTEGER PRIMARY KEY, asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  name TEXT, mac TEXT, ip TEXT, subnet TEXT, gateway TEXT, dns TEXT, dhcp INTEGER);
CREATE INDEX IF NOT EXISTS ix_nics_asset ON asset_nics(asset_id);

CREATE TABLE IF NOT EXISTS software(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, publisher TEXT NOT NULL DEFAULT '',
  category TEXT, status TEXT NOT NULL DEFAULT 'neutral', notes TEXT, first_seen TEXT DEFAULT ${NOW},
  UNIQUE(name, publisher));

CREATE TABLE IF NOT EXISTS asset_software(
  asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  software_id INTEGER NOT NULL REFERENCES software(id) ON DELETE CASCADE,
  version TEXT NOT NULL DEFAULT '', install_date TEXT,
  PRIMARY KEY(asset_id, software_id, version));
CREATE INDEX IF NOT EXISTS ix_assetsw_sw ON asset_software(software_id);

CREATE TABLE IF NOT EXISTS asset_updates(
  asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  hotfix_id TEXT NOT NULL, description TEXT, installed_on TEXT, PRIMARY KEY(asset_id, hotfix_id));

CREATE TABLE IF NOT EXISTS asset_history(
  id INTEGER PRIMARY KEY, asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  ts TEXT DEFAULT ${NOW}, kind TEXT NOT NULL, field TEXT, old_value TEXT, new_value TEXT, actor TEXT);
CREATE INDEX IF NOT EXISTS ix_history_asset ON asset_history(asset_id, ts);
CREATE INDEX IF NOT EXISTS ix_history_ts ON asset_history(ts);

CREATE TABLE IF NOT EXISTS agents(
  id TEXT PRIMARY KEY, asset_id INTEGER UNIQUE REFERENCES assets(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL, version TEXT, enrolled_at TEXT DEFAULT ${NOW},
  last_checkin TEXT, last_heartbeat TEXT, last_ip TEXT, scan_requested INTEGER NOT NULL DEFAULT 0);

CREATE TABLE IF NOT EXISTS licenses(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, software_match TEXT, vendor TEXT,
  license_type TEXT NOT NULL DEFAULT 'per_device', seats INTEGER, cost REAL,
  purchase_date TEXT, expiry_date TEXT, license_key TEXT, notes TEXT);

CREATE TABLE IF NOT EXISTS contracts(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, vendor TEXT, contract_type TEXT NOT NULL DEFAULT 'support',
  number TEXT, start_date TEXT, end_date TEXT, cost REAL, renewal TEXT, notes TEXT);
CREATE TABLE IF NOT EXISTS contract_assets(
  contract_id INTEGER NOT NULL REFERENCES contracts(id) ON DELETE CASCADE,
  asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE, PRIMARY KEY(contract_id, asset_id));

CREATE TABLE IF NOT EXISTS asset_relations(
  id INTEGER PRIMARY KEY,
  from_asset INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  to_asset INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  rel_type TEXT NOT NULL, UNIQUE(from_asset, to_asset, rel_type));

CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY, key TEXT NOT NULL, asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
  kind TEXT NOT NULL, severity TEXT NOT NULL, message TEXT NOT NULL,
  created_at TEXT DEFAULT ${NOW}, resolved_at TEXT, acknowledged INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_alerts_open ON alerts(resolved_at, key);

CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY, ts TEXT DEFAULT ${NOW}, username TEXT, action TEXT, entity TEXT, entity_id TEXT, detail TEXT);

CREATE TABLE IF NOT EXISTS discovery_results(
  id INTEGER PRIMARY KEY, ip TEXT UNIQUE NOT NULL, hostname TEXT, mac TEXT, open_ports TEXT, guess_type TEXT,
  first_seen TEXT DEFAULT ${NOW}, last_seen TEXT DEFAULT ${NOW},
  asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL);
`;

function norm(v) {
  if (v === undefined) return null;
  if (typeof v === 'boolean') return v ? 1 : 0;
  if (v !== null && typeof v === 'object' && !Buffer.isBuffer(v)) return JSON.stringify(v);
  return v;
}

export class Db {
  constructor(file) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    this.db = new DatabaseSync(file);
    this.cache = new Map();
    this.inTx = false;
    this.db.exec('PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;');
    this.db.exec(SCHEMA);
    this.migrate();
    this.migrateCatalog();
  }
  addColumn(table, col, def) {
    const cols = this.db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name);
    if (!cols.includes(col)) this.db.exec(`ALTER TABLE ${table} ADD COLUMN ${col} ${def}`);
  }
  migrate() {
    this.addColumn('agents', 'secret_enc', 'TEXT');
    this.addColumn('sessions', 'last_seen', 'INTEGER');
    this.addColumn('sessions', 'ip', 'TEXT');
    this.addColumn('sessions', 'user_agent', 'TEXT');
    this.addColumn('users', 'totp_secret_enc', 'TEXT');
    this.addColumn('users', 'totp_pending_enc', 'TEXT');
    this.addColumn('users', 'totp_enabled', 'INTEGER NOT NULL DEFAULT 0');
    this.addColumn('users', 'totp_last_step', 'INTEGER NOT NULL DEFAULT 0');
    this.exec(`
      CREATE TABLE IF NOT EXISTS activity_events(
        id INTEGER PRIMARY KEY, asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
        ts TEXT NOT NULL, end_ts TEXT, seconds INTEGER NOT NULL DEFAULT 0, active_seconds INTEGER NOT NULL DEFAULT 0,
        process TEXT, app TEXT, title TEXT, category TEXT, os_user TEXT);
      CREATE INDEX IF NOT EXISTS ix_act_asset ON activity_events(asset_id, ts);
      CREATE INDEX IF NOT EXISTS ix_act_ts ON activity_events(ts);

      CREATE TABLE IF NOT EXISTS screenshots(
        id INTEGER PRIMARY KEY, asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
        ts TEXT NOT NULL, process TEXT, app TEXT, title TEXT, os_user TEXT,
        width INTEGER, height INTEGER, monitors INTEGER, bytes INTEGER, file TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS ix_shot_asset ON screenshots(asset_id, ts);
      CREATE INDEX IF NOT EXISTS ix_shot_ts ON screenshots(ts);

      CREATE TABLE IF NOT EXISTS location_samples(
        id INTEGER PRIMARY KEY, asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
        ts TEXT NOT NULL, method TEXT, ssid TEXT, bssid TEXT, public_ip TEXT, private_ip TEXT,
        lat REAL, lng REAL, accuracy REAL, label TEXT, os_user TEXT);
      CREATE INDEX IF NOT EXISTS ix_loc_asset ON location_samples(asset_id, ts);`);
    this.addColumn('assets', 'cur_app', 'TEXT');
    this.addColumn('assets', 'cur_title', 'TEXT');
    this.addColumn('assets', 'cur_os_user', 'TEXT');
    this.addColumn('assets', 'activity_at', 'TEXT');
    this.addColumn('assets', 'loc_label', 'TEXT');
    this.addColumn('assets', 'loc_at', 'TEXT');
    // enterprise: tamper-evident audit, API tokens, check-out/check-in
    this.addColumn('audit_log', 'prev_hash', 'TEXT');
    this.addColumn('audit_log', 'hash', 'TEXT');
    this.addColumn('audit_log', 'ip', 'TEXT');
    this.addColumn('users', 'password_changed_at', 'TEXT');
    this.exec(`
      CREATE TABLE IF NOT EXISTS api_tokens(
        id INTEGER PRIMARY KEY, name TEXT NOT NULL, prefix TEXT UNIQUE NOT NULL, token_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'viewer', created_by TEXT, created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
        expires_at TEXT, last_used_at TEXT, last_ip TEXT, revoked INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS asset_checkouts(
        id INTEGER PRIMARY KEY, asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
        person_id INTEGER REFERENCES people(id) ON DELETE SET NULL, out_at TEXT NOT NULL, due_at TEXT,
        in_at TEXT, out_by TEXT, in_by TEXT, out_notes TEXT, in_notes TEXT, in_condition TEXT);
      CREATE INDEX IF NOT EXISTS ix_co_open ON asset_checkouts(asset_id, in_at);`);
    this.exec(`
      CREATE TABLE IF NOT EXISTS perm_groups(
        id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, description TEXT, perms TEXT NOT NULL DEFAULT '[]');
      CREATE TABLE IF NOT EXISTS stock_items(
        id INTEGER PRIMARY KEY, kind TEXT NOT NULL DEFAULT 'accessory', name TEXT NOT NULL, category TEXT, manufacturer TEXT,
        model_number TEXT, location_id INTEGER REFERENCES locations(id) ON DELETE SET NULL, supplier TEXT,
        qty_total INTEGER NOT NULL DEFAULT 0, min_qty INTEGER NOT NULL DEFAULT 0, unit_cost REAL, notes TEXT,
        created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
      CREATE TABLE IF NOT EXISTS stock_moves(
        id INTEGER PRIMARY KEY, item_id INTEGER NOT NULL REFERENCES stock_items(id) ON DELETE CASCADE,
        action TEXT NOT NULL, qty INTEGER NOT NULL, person_id INTEGER REFERENCES people(id) ON DELETE SET NULL,
        returned INTEGER NOT NULL DEFAULT 0, ts TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), by_user TEXT, notes TEXT);
      CREATE INDEX IF NOT EXISTS ix_moves_item ON stock_moves(item_id, action, returned);`);
    // Snipe-IT-style inventory & users: permission groups, self-service users, stock, acceptance, audits, map
    this.addColumn('users', 'person_id', 'INTEGER REFERENCES people(id) ON DELETE SET NULL');
    this.addColumn('users', 'group_id', 'INTEGER REFERENCES perm_groups(id) ON DELETE SET NULL');
    this.addColumn('asset_checkouts', 'location_id', 'INTEGER REFERENCES locations(id) ON DELETE SET NULL');
    this.addColumn('asset_checkouts', 'accept_status', 'TEXT');          // NULL (not required) | pending | accepted | declined
    this.addColumn('asset_checkouts', 'accept_at', 'TEXT');
    this.addColumn('asset_checkouts', 'accept_note', 'TEXT');
    this.addColumn('asset_checkouts', 'accept_name', 'TEXT');
    this.addColumn('assets', 'last_audit_at', 'TEXT');
    this.addColumn('assets', 'next_audit_date', 'TEXT');
    this.addColumn('locations', 'lat', 'REAL');
    this.addColumn('locations', 'lng', 'REAL');
  }
  migrateCatalog() {
    this.exec(`
      CREATE TABLE IF NOT EXISTS companies(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE, phone TEXT, email TEXT, notes TEXT);
      CREATE TABLE IF NOT EXISTS manufacturers(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE, url TEXT, support_url TEXT, support_email TEXT, support_phone TEXT, notes TEXT);
      CREATE TABLE IF NOT EXISTS suppliers(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE, contact TEXT, email TEXT, phone TEXT, address TEXT, url TEXT, notes TEXT);
      CREATE TABLE IF NOT EXISTS categories(id INTEGER PRIMARY KEY, name TEXT NOT NULL COLLATE NOCASE, kind TEXT NOT NULL DEFAULT 'asset', notes TEXT, UNIQUE(name, kind));
      CREATE TABLE IF NOT EXISTS asset_models(
        id INTEGER PRIMARY KEY, name TEXT NOT NULL COLLATE NOCASE, model_number TEXT COLLATE NOCASE,
        manufacturer_id INTEGER REFERENCES manufacturers(id) ON DELETE SET NULL, category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
        asset_type TEXT, eol_months INTEGER, notes TEXT, UNIQUE(name, model_number));
      CREATE TABLE IF NOT EXISTS import_files(
        id INTEGER PRIMARY KEY, name TEXT NOT NULL, size INTEGER NOT NULL, rows INTEGER, file TEXT NOT NULL, created_by TEXT,
        created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), last_type TEXT, last_run_at TEXT, last_result TEXT, last_mapping TEXT);`);
    this.addColumn('assets', 'company_id', 'INTEGER REFERENCES companies(id) ON DELETE SET NULL');
    this.addColumn('assets', 'model_id', 'INTEGER REFERENCES asset_models(id) ON DELETE SET NULL');
    this.addColumn('assets', 'supplier_id', 'INTEGER REFERENCES suppliers(id) ON DELETE SET NULL');
    this.addColumn('people', 'company_id', 'INTEGER REFERENCES companies(id) ON DELETE SET NULL');
    this.addColumn('people', 'employee_number', 'TEXT');
    this.addColumn('stock_items', 'order_number', 'TEXT');
    this.addColumn('stock_items', 'purchase_date', 'TEXT');
    this.addColumn('stock_items', 'company_id', 'INTEGER REFERENCES companies(id) ON DELETE SET NULL');
    this.addColumn('licenses', 'order_number', 'TEXT');
    this.addColumn('licenses', 'company_id', 'INTEGER REFERENCES companies(id) ON DELETE SET NULL');
  }
  stmt(sql) {
    let s = this.cache.get(sql);
    if (!s) { s = this.db.prepare(sql); this.cache.set(sql, s); }
    return s;
  }
  all(sql, ...p) { return this.stmt(sql).all(...p.map(norm)); }
  get(sql, ...p) { return this.stmt(sql).get(...p.map(norm)); }
  run(sql, ...p) { return this.stmt(sql).run(...p.map(norm)); }
  exec(sql) { this.db.exec(sql); }
  tx(fn) {
    if (this.inTx) return fn();
    this.db.exec('BEGIN');
    this.inTx = true;
    try { const r = fn(); this.db.exec('COMMIT'); return r; }
    catch (e) { this.db.exec('ROLLBACK'); throw e; }
    finally { this.inTx = false; }
  }
  insert(table, obj) {
    const keys = Object.keys(obj);
    const r = this.run(`INSERT INTO ${table}(${keys.join(',')}) VALUES(${keys.map(() => '?').join(',')})`, ...keys.map(k => obj[k]));
    return Number(r.lastInsertRowid);
  }
  update(table, id, obj) {
    const keys = Object.keys(obj);
    if (!keys.length) return;
    this.run(`UPDATE ${table} SET ${keys.map(k => `${k}=?`).join(',')} WHERE id=?`, ...keys.map(k => obj[k]), id);
  }
  setting(key, def = null) {
    const r = this.get('SELECT value FROM settings WHERE key=?', key);
    return r ? r.value : def;
  }
  setSetting(key, value) {
    this.run('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', key, String(value));
  }
}

export const DEFAULT_SETTINGS = {
  org_name: 'My Organization',
  asset_tag_prefix: 'AST-',
  agent_interval_min: '60',
  offline_days: '7',
  low_disk_pct: '10',
  warranty_alert_days: '30',
  license_alert_days: '30',
  contract_alert_days: '30',
  depreciation_years: '4',
  currency: 'USD',
  session_idle_min: '30',
  session_max_hours: '12',
  require_2fa_admins: '0',
  monitoring_enabled: '0',
  activity_enabled: '1',
  screenshot_enabled: '0',
  screenshot_interval_min: '15',
  idle_threshold_sec: '300',
  location_enabled: '0',
  monitoring_retention_days: '30',
  portal_ip_allowlist: '',
  webhook_kind: 'generic',
  webhook_min_severity: 'warning',
  uninstall_protection: '0',
  password_max_age_days: '0',
  require_acceptance: '0',
  audit_interval_months: '12',
  eula_text: 'By accepting, I confirm I have received this equipment in good condition and will use it according to company IT policy.',
  monitoring_notice: 'This computer is managed by IT. Application usage, active window titles and periodic screenshots may be recorded for security and compliance while you are signed in.',
};
