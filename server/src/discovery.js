import net from 'node:net';
import dns from 'node:dns/promises';
import { execFile } from 'node:child_process';
import { nowIso } from './inventory.js';

const PORTS = [22, 23, 80, 135, 161, 443, 445, 515, 631, 3389, 5900, 8080, 9100];
const isWin = process.platform === 'win32';

export function expandTargets(spec) {
  const out = [];
  for (const part of String(spec).split(/[,\s]+/).filter(Boolean)) {
    let m;
    if ((m = /^(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})$/.exec(part))) {
      const bits = Number(m[2]);
      if (bits < 20 || bits > 32) throw new Error('CIDR prefix must be between /20 and /32');
      const base = ipToInt(m[1]) & (bits === 32 ? 0xffffffff : (~((1 << (32 - bits)) - 1)) >>> 0);
      const size = 2 ** (32 - bits);
      for (let i = size > 2 ? 1 : 0; i < (size > 2 ? size - 1 : size); i++) out.push(intToIp((base + i) >>> 0));
    } else if ((m = /^(\d+\.\d+\.\d+)\.(\d+)-(\d+)$/.exec(part))) {
      for (let i = Number(m[2]); i <= Math.min(255, Number(m[3])); i++) out.push(`${m[1]}.${i}`);
    } else if (/^\d+\.\d+\.\d+\.\d+$/.test(part)) out.push(part);
    else throw new Error(`Invalid target: ${part}`);
  }
  if (out.length > 4096) throw new Error('Too many addresses (max 4096 per scan)');
  return [...new Set(out)];
}
const ipToInt = (ip) => ip.split('.').reduce((a, o) => ((a << 8) + Number(o)) >>> 0, 0);
const intToIp = (n) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');

function ping(ip) {
  return new Promise((resolve) => {
    const args = isWin ? ['-n', '1', '-w', '600', ip] : ['-c', '1', '-W', '1', ip];
    execFile('ping', args, { timeout: 3000, windowsHide: true }, (err, stdout) => {
      resolve(/ttl[=:]/i.test(String(stdout)));
    });
  });
}

function probe(ip, port, timeout = 700) {
  return new Promise((resolve) => {
    const s = net.connect({ host: ip, port });
    const done = (ok) => { s.destroy(); resolve(ok); };
    s.setTimeout(timeout, () => done(false));
    s.once('connect', () => done(true));
    s.once('error', () => done(false));
  });
}

function arpTable() {
  return new Promise((resolve) => {
    execFile('arp', ['-a'], { timeout: 5000, windowsHide: true }, (err, stdout) => {
      const map = new Map();
      for (const line of String(stdout || '').split(/\r?\n/)) {
        const m = /(\d+\.\d+\.\d+\.\d+)\)?\s+(?:at\s+)?([0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2})/i.exec(line);
        if (m) map.set(m[1], m[2].replace(/-/g, ':').toUpperCase());
      }
      resolve(map);
    });
  });
}

function guess(ports) {
  const has = (p) => ports.includes(p);
  if (has(9100) || has(515) || has(631)) return 'printer';
  if (has(3389) || (has(135) && has(445))) return 'workstation';
  if (has(161) || has(23)) return 'network';
  if (has(22) && !has(445)) return 'server';
  if (has(5900)) return 'workstation';
  if (has(80) || has(443) || has(8080)) return 'network';
  return 'other';
}

async function pool(items, n, fn) {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const idx = i++; await fn(items[idx]); }
  }));
}

export class DiscoveryService {
  constructor(db) { this.db = db; this.job = null; }
  status() { return this.job; }
  start(spec, user) {
    if (this.job?.running) throw new Error('A scan is already running');
    const targets = expandTargets(spec);
    const job = this.job = { targets: spec, total: targets.length, done: 0, found: 0, running: true, started_at: nowIso(), by: user, error: null };
    (async () => {
      const alive = [];
      await pool(targets, 64, async (ip) => {
        const [up, ports] = await Promise.all([ping(ip), Promise.all(PORTS.map((p) => probe(ip, p).then((ok) => (ok ? p : null))))]);
        const open = ports.filter(Boolean);
        if (up || open.length) { alive.push({ ip, open }); job.found++; }
        job.done++;
      });
      const arp = await arpTable();
      for (const h of alive) {
        let hostname = null;
        try { hostname = (await dns.reverse(h.ip))[0] || null; } catch { /* no PTR */ }
        const mac = arp.get(h.ip) || null;
        const asset = this.db.get('SELECT id FROM assets WHERE ip=? OR (mac IS NOT NULL AND mac=?) OR id IN (SELECT asset_id FROM asset_nics WHERE (\', \' || ip || \',\') LIKE ? OR (mac IS NOT NULL AND mac=?)) LIMIT 1',
          h.ip, mac, `%, ${h.ip},%`, mac);
        this.db.run(`INSERT INTO discovery_results(ip,hostname,mac,open_ports,guess_type,asset_id,last_seen) VALUES(?,?,?,?,?,?,?)
          ON CONFLICT(ip) DO UPDATE SET hostname=COALESCE(excluded.hostname,hostname), mac=COALESCE(excluded.mac,mac),
          open_ports=excluded.open_ports, guess_type=excluded.guess_type, asset_id=COALESCE(excluded.asset_id,asset_id), last_seen=excluded.last_seen`,
          h.ip, hostname, mac, h.open.join(','), guess(h.open), asset?.id ?? null, nowIso());
      }
    })().catch((e) => { job.error = e.message; }).finally(() => { job.running = false; job.finished_at = nowIso(); });
    return job;
  }
}
