// Activity, screenshot and location monitoring: ingestion, roll-ups, retention.
// Transparent, on managed devices only; no keystroke/credential capture (active window titles only).
import fs from 'node:fs';
import path from 'node:path';
import { nowIso } from './inventory.js';

const str = (v, max = 400) => (v === null || v === undefined || v === '' ? null : String(v).slice(0, max));
const int = (v) => (v === null || v === undefined || v === '' || isNaN(Number(v)) ? null : Math.round(Number(v)));
// Accept ISO strings or unix seconds/ms; always store ISO so range queries work.
function isoTs(v) {
  if (v === null || v === undefined || v === '') return nowIso();
  if (typeof v === 'number' || /^\d+$/.test(String(v))) {
    const n = Number(v);
    const d = new Date(n < 1e12 ? n * 1000 : n);
    return isNaN(d) ? nowIso() : d.toISOString();
  }
  const d = new Date(v);
  return isNaN(d) ? nowIso() : d.toISOString();
}

// Best-effort classification of a process into a usage category for reporting.
const CATEGORIES = [
  ['Browsing', /chrome|msedge|firefox|opera|brave|iexplore|safari/i],
  ['Email & chat', /outlook|thunderbird|teams|slack|zoom|webex|discord|skype|whatsapp/i],
  ['Office & docs', /winword|excel|powerpnt|onenote|acrobat|acrord32|wps|soffice|notepad|obsidian/i],
  ['Development', /code|devenv|pycharm|idea|studio|sublime|windowsterminal|cmd|powershell|wsl|docker|git/i],
  ['Design & media', /photoshop|illustrator|figma|blender|premiere|vlc|spotify|obs/i],
  ['System & admin', /explorer|mmc|taskmgr|regedit|control|SystemSettings|dllhost/i],
  ['Games', /steam|epicgames|battle\.net|riotclient/i],
];
function categorize(process, title) {
  const s = `${process || ''} ${title || ''}`;
  for (const [name, re] of CATEGORIES) if (re.test(s)) return name;
  return 'Other';
}
function appName(process) {
  if (!process) return null;
  return process.replace(/\.exe$/i, '').replace(/^./, (c) => c.toUpperCase());
}

export class Monitoring {
  constructor(db, vault, dir) {
    this.db = db;
    this.vault = vault;
    this.dir = dir;
    fs.mkdirSync(dir, { recursive: true });
  }

  enabled() { return this.db.setting('monitoring_enabled') === '1'; }

  /** Policy handed to the per-user agent helper so it knows what to collect. */
  policy() {
    const on = this.enabled();
    const s = (k, d) => Number(this.db.setting(k, d));
    return {
      enabled: on,
      activity: on && this.db.setting('activity_enabled', '1') === '1',
      screenshots: on && this.db.setting('screenshot_enabled') === '1',
      screenshot_interval_min: Math.max(1, s('screenshot_interval_min', 15)),
      idle_threshold_sec: Math.max(30, s('idle_threshold_sec', 300)),
      location: on && this.db.setting('location_enabled') === '1',
      notice: this.db.setting('monitoring_notice', ''),
    };
  }

  ingestActivity(agent, msg) {
    if (!this.enabled()) return;
    const events = Array.isArray(msg.events) ? msg.events.slice(0, 2000) : [];
    this.db.tx(() => {
      let last = null;
      for (const e of events) {
        const process = str(e.process, 120);
        const row = {
          asset_id: agent.asset_id, ts: isoTs(e.ts), end_ts: e.end_ts ? isoTs(e.end_ts) : null,
          seconds: int(e.seconds) || 0, active_seconds: int(e.active_seconds) ?? int(e.seconds) ?? 0,
          process, app: appName(process), title: str(e.title, 300), category: categorize(process, e.title), os_user: str(e.os_user, 120),
        };
        this.db.insert('activity_events', row);
        if (!last || (row.end_ts || row.ts) >= (last.end_ts || last.ts)) last = row;
      }
      if (last) {
        this.db.run('UPDATE assets SET cur_app=?, cur_title=?, cur_os_user=?, activity_at=?, last_seen=? WHERE id=?',
          last.app, last.title, last.os_user, last.end_ts || last.ts, nowIso(), agent.asset_id);
      }
    });
  }

  ingestLocation(agent, msg) {
    if (!this.enabled()) return;
    const label = str(msg.label, 200) || str(msg.ssid, 200) || (msg.lat != null ? `${msg.lat.toFixed(3)}, ${msg.lng?.toFixed(3)}` : null);
    this.db.insert('location_samples', {
      asset_id: agent.asset_id, ts: isoTs(msg.ts), method: str(msg.method, 40),
      ssid: str(msg.ssid, 200), bssid: str(msg.bssid, 200), public_ip: str(msg.public_ip, 60), private_ip: str(msg.private_ip, 200),
      lat: msg.lat == null ? null : Number(msg.lat), lng: msg.lng == null ? null : Number(msg.lng),
      accuracy: msg.accuracy == null ? null : Number(msg.accuracy), label, os_user: str(msg.os_user, 120),
    });
    this.db.run('UPDATE assets SET loc_label=?, loc_at=?, last_seen=? WHERE id=?', label, nowIso(), nowIso(), agent.asset_id);
  }

  saveScreenshot(agent, msg) {
    if (!this.enabled() || this.db.setting('screenshot_enabled') !== '1') return { ok: false };
    const img = Buffer.from(String(msg.img || ''), 'base64');
    if (!img.length || img.length > 8 * 1024 * 1024) throw new Error('bad image');
    const tsIso = isoTs(msg.ts); const day = tsIso.slice(0, 10);
    const rel = path.join(String(agent.asset_id), day, `${Date.now()}-${Math.random().toString(36).slice(2, 8)}.enc`);
    const abs = path.join(this.dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, this.vault.encBytes(img));
    const process = str(msg.process, 120);
    this.db.insert('screenshots', {
      asset_id: agent.asset_id, ts: tsIso, process, app: appName(process), title: str(msg.title, 300),
      os_user: str(msg.os_user, 120), width: int(msg.width), height: int(msg.height), monitors: int(msg.monitors) || 1,
      bytes: img.length, file: rel.replace(/\\/g, '/'),
    });
    return { ok: true };
  }

  readScreenshot(row) {
    const abs = path.join(this.dir, row.file);
    if (!path.resolve(abs).startsWith(path.resolve(this.dir))) return null;
    try { return this.vault.decBytes(fs.readFileSync(abs)); } catch { return null; }
  }

  retention() {
    const days = Math.max(1, Number(this.db.setting('monitoring_retention_days', 30)) || 30);
    const cut = new Date(Date.now() - days * 86400000).toISOString();
    this.db.run('DELETE FROM activity_events WHERE ts < ?', cut);
    this.db.run('DELETE FROM location_samples WHERE ts < ?', cut);
    for (const s of this.db.all('SELECT id, file FROM screenshots WHERE ts < ?', cut)) {
      try { fs.unlinkSync(path.join(this.dir, s.file)); } catch { /* already gone */ }
      this.db.run('DELETE FROM screenshots WHERE id=?', s.id);
    }
  }
}
