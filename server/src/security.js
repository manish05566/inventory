// Server-side security controls: rate limiting, IP allowlist, tamper-evident audit log,
// scoped API tokens and passphrase-encrypted backups.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

// ---------------------------------------------------------------- rate limiting (sliding window per key)
export class RateLimiter {
  constructor() { this.buckets = new Map(); setInterval(() => this.sweep(), 60000).unref(); }
  /** Returns true when the request is allowed. */
  hit(key, limit, windowMs = 60000) {
    const now = Date.now();
    let b = this.buckets.get(key);
    if (!b || now - b.start > windowMs) { b = { start: now, n: 0 }; this.buckets.set(key, b); }
    b.n++;
    return b.n <= limit;
  }
  sweep() { const now = Date.now(); for (const [k, b] of this.buckets) if (now - b.start > 120000) this.buckets.delete(k); }
}

// ---------------------------------------------------------------- IP allowlist
const v4 = (ip) => {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip);
  return m ? m.slice(1).reduce((a, o) => ((a << 8) + Number(o)) >>> 0, 0) : null;
};
export function parseAllowlist(text) {
  const rules = [];
  for (const raw of String(text || '').split(/[\s,;]+/).filter(Boolean)) {
    const [ip, bitsS] = raw.split('/');
    if (v4(ip) !== null) {
      const bits = bitsS === undefined ? 32 : Number(bitsS);
      if (!(bits >= 0 && bits <= 32)) throw new Error(`Invalid CIDR: ${raw}`);
      const mask = bits === 0 ? 0 : (~((1 << (32 - bits)) - 1)) >>> 0;
      rules.push({ kind: 4, base: v4(ip) & mask, mask });
    } else if (/^[0-9a-f:]+$/i.test(ip) && bitsS === undefined) rules.push({ kind: 6, ip: ip.toLowerCase() });
    else throw new Error(`Invalid address: ${raw}`);
  }
  return rules;
}
export function ipAllowed(ip, rules) {
  if (!rules.length) return true;
  if (ip === '127.0.0.1' || ip === '::1') return true; // never lock out the server console
  const n = v4(ip);
  return rules.some((r) => (r.kind === 4 ? n !== null && (n & r.mask) === r.base : r.ip === String(ip).toLowerCase()));
}

// ---------------------------------------------------------------- tamper-evident audit log (hash chain)
const auditHash = (prev, r) => sha256([prev || '', r.ts, r.username || '', r.action || '', r.entity || '', r.entity_id || '', r.detail || ''].join('\u001f'));
export function auditAppend(db, { username, action, entity, entity_id, detail, ip }) {
  const last = db.get('SELECT hash FROM audit_log WHERE hash IS NOT NULL ORDER BY id DESC LIMIT 1');
  const row = { ts: new Date().toISOString(), username: username || 'system', action, entity, entity_id: entity_id ?? null,
    detail: detail ? String(detail).slice(0, 4000) : null, ip: ip || null };
  row.prev_hash = last?.hash || null;
  row.hash = auditHash(row.prev_hash, row);
  db.insert('audit_log', row);
}
/** Walks the chain; returns { ok, checked, broken_at } */
export function auditVerify(db) {
  let prev = null, checked = 0;
  for (const r of db.all('SELECT * FROM audit_log WHERE hash IS NOT NULL ORDER BY id')) {
    if (r.prev_hash !== prev || auditHash(prev, r) !== r.hash) return { ok: false, checked, broken_at: r.id };
    prev = r.hash; checked++;
  }
  return { ok: true, checked, broken_at: null };
}

// ---------------------------------------------------------------- API tokens  (format: ap_<prefix>_<secret>)
export function createToken(db, { name, role, days, by }) {
  const prefix = crypto.randomBytes(4).toString('hex');
  const secret = crypto.randomBytes(24).toString('base64url');
  const id = db.insert('api_tokens', {
    name, prefix, token_hash: sha256(secret), role, created_by: by,
    expires_at: days ? new Date(Date.now() + days * 86400000).toISOString() : null,
  });
  return { id, token: `ap_${prefix}_${secret}` };
}
export function verifyToken(db, header) {
  const m = /^Bearer\s+ap_([0-9a-f]{8})_([A-Za-z0-9_-]{20,})$/.exec(header || '');
  if (!m) return null;
  const t = db.get('SELECT * FROM api_tokens WHERE prefix=? AND revoked=0', m[1]);
  if (!t) return null;
  const a = Buffer.from(t.token_hash), b = Buffer.from(sha256(m[2]));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  if (t.expires_at && t.expires_at < new Date().toISOString()) return null;
  return t;
}

// ---------------------------------------------------------------- encrypted backups
// File: "APBAK1" | salt(16) | nonce(12) | AES-256-GCM(gzip(JSON{db, master_key})) | tag(16)
const MAGIC = Buffer.from('APBAK1');
export function createBackup(db, dataDir, passphrase) {
  const tmp = path.join(os.tmpdir(), `apbak-${crypto.randomBytes(6).toString('hex')}.db`);
  db.exec(`VACUUM INTO '${tmp.replace(/'/g, "''")}'`);
  try {
    const payload = zlib.gzipSync(Buffer.from(JSON.stringify({
      format: 1, created: new Date().toISOString(), host: os.hostname(),
      db: fs.readFileSync(tmp).toString('base64'),
      master_key: fs.existsSync(path.join(dataDir, 'master.key')) ? fs.readFileSync(path.join(dataDir, 'master.key'), 'utf8').trim() : (process.env.MASTER_KEY || null),
    })));
    const salt = crypto.randomBytes(16), n = crypto.randomBytes(12);
    const key = crypto.scryptSync(passphrase, salt, 32, { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
    const c = crypto.createCipheriv('aes-256-gcm', key, n);
    return Buffer.concat([MAGIC, salt, n, c.update(payload), c.final(), c.getAuthTag()]);
  } finally { fs.rmSync(tmp, { force: true }); }
}
export function openBackup(buf, passphrase) {
  if (!buf.subarray(0, 6).equals(MAGIC)) throw new Error('Not an Asset Portal backup file');
  const salt = buf.subarray(6, 22), n = buf.subarray(22, 34), tag = buf.subarray(buf.length - 16);
  const key = crypto.scryptSync(passphrase, salt, 32, { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  const d = crypto.createDecipheriv('aes-256-gcm', key, n);
  d.setAuthTag(tag);
  let plain;
  try { plain = Buffer.concat([d.update(buf.subarray(34, buf.length - 16)), d.final()]); }
  catch { throw new Error('Wrong passphrase or corrupted backup'); }
  return JSON.parse(zlib.gunzipSync(plain).toString('utf8'));
}
