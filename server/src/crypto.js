// Cryptography for the portal:
//  - master key (AES-256-GCM) protecting secrets at rest in the database
//  - server X25519 identity used for end-to-end encrypted agent traffic
//  - TOTP (RFC 6238) for two-factor login
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';

const SPKI_X25519 = Buffer.from('302a300506032b656e032100', 'hex');
const PKCS8_X25519 = Buffer.from('302e020100300506032b656e04220420', 'hex');

export class Crypto {
  constructor(db, dataDir) {
    this.db = db;
    this.master = this.loadMasterKey(dataDir);
    let pub = db.setting('server_x25519_pub');
    if (!pub) {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
      pub = publicKey.export({ type: 'spki', format: 'der' }).subarray(12).toString('base64');
      db.setSetting('server_x25519_priv', this.encrypt(privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(16).toString('base64')));
      db.setSetting('server_x25519_pub', pub);
    }
    this.serverPub = Buffer.from(pub, 'base64');
    this.serverPriv = crypto.createPrivateKey({
      key: Buffer.concat([PKCS8_X25519, Buffer.from(this.decrypt(db.setting('server_x25519_priv')), 'base64')]), format: 'der', type: 'pkcs8',
    });
    this.seen = new Map(); // replay cache: nonce -> expiry
    setInterval(() => { const now = Date.now(); for (const [k, exp] of this.seen) if (exp < now) this.seen.delete(k); }, 60000).unref();
  }

  loadMasterKey(dataDir) {
    if (process.env.MASTER_KEY) {
      const k = Buffer.from(process.env.MASTER_KEY, 'base64');
      if (k.length !== 32) throw new Error('MASTER_KEY must be 32 bytes, base64 encoded');
      return k;
    }
    const file = path.join(dataDir, 'master.key');
    if (!fs.existsSync(file)) {
      fs.writeFileSync(file, crypto.randomBytes(32).toString('base64'), { mode: 0o600 });
      console.log(`[init] Generated master encryption key at ${file} — back it up together with the database.`);
    }
    return Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'base64');
  }

  /** Fingerprint shown to admins / agents to verify the server identity. */
  get fingerprint() {
    return crypto.createHash('sha256').update(this.serverPub).digest('hex').slice(0, 32).toUpperCase().match(/.{4}/g).join('-');
  }

  // ---------- at-rest field encryption ----------
  encrypt(text) {
    if (text === null || text === undefined || text === '') return text ?? null;
    const n = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', this.master, n);
    const ct = Buffer.concat([c.update(String(text), 'utf8'), c.final(), c.getAuthTag()]);
    return `enc:v1:${Buffer.concat([n, ct]).toString('base64')}`;
  }
  decrypt(value) {
    if (!value || !String(value).startsWith('enc:v1:')) return value ?? null;
    const b = Buffer.from(String(value).slice(7), 'base64');
    const d = crypto.createDecipheriv('aes-256-gcm', this.master, b.subarray(0, 12));
    d.setAuthTag(b.subarray(b.length - 16));
    return Buffer.concat([d.update(b.subarray(12, b.length - 16)), d.final()]).toString('utf8');
  }

  // ---------- binary blobs at rest (screenshots) ----------
  encBytes(buf) {
    const n = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', this.master, n);
    return Buffer.concat([n, c.update(buf), c.final(), c.getAuthTag()]);
  }
  decBytes(b) {
    const d = crypto.createDecipheriv('aes-256-gcm', this.master, b.subarray(0, 12));
    d.setAuthTag(b.subarray(b.length - 16));
    return Buffer.concat([d.update(b.subarray(12, b.length - 16)), d.final()]);
  }

  // ---------- agent transport ----------
  static hkdf(ikm, salt, info) { return Buffer.from(crypto.hkdfSync('sha256', ikm, salt, Buffer.from(info), 32)); }
  static seal(key, obj, aad) {
    const n = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', key, n);
    c.setAAD(Buffer.from(aad));
    const ct = Buffer.concat([c.update(zlib.gzipSync(Buffer.from(JSON.stringify(obj)))), c.final(), c.getAuthTag()]);
    return { n: n.toString('base64'), ct: ct.toString('base64') };
  }
  static open(key, n, ct, aad) {
    const b = Buffer.from(String(ct), 'base64');
    const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(String(n), 'base64'));
    d.setAAD(Buffer.from(aad));
    d.setAuthTag(b.subarray(b.length - 16));
    const plain = Buffer.concat([d.update(b.subarray(0, b.length - 16)), d.final()]);
    return JSON.parse(zlib.gunzipSync(plain, { maxOutputLength: 64 * 1024 * 1024 }).toString('utf8'));
  }
  /** Rejects stale or replayed messages. ts = unix seconds. */
  checkFresh(ts, nonce) {
    if (!Number.isFinite(Number(ts)) || Math.abs(Date.now() / 1000 - Number(ts)) > 300) throw new Error('stale message (check the client clock)');
    if (this.seen.has(nonce)) throw new Error('replayed message');
    this.seen.set(nonce, Date.now() + 11 * 60000);
  }
  /** Key for an enrollment exchange: ECDH(agent ephemeral, server identity). */
  enrollKey(epkB64) {
    const epk = Buffer.from(String(epkB64), 'base64');
    if (epk.length !== 32) throw new Error('bad key');
    const shared = crypto.diffieHellman({ privateKey: this.serverPriv, publicKey: crypto.createPublicKey({ key: Buffer.concat([SPKI_X25519, epk]), format: 'der', type: 'spki' }) });
    return Crypto.hkdf(shared, Buffer.concat([epk, this.serverPub]), 'assetagent/enroll/v2');
  }
  static messageKey(secret, agentId) { return Crypto.hkdf(secret, Buffer.from(agentId), 'assetagent/msg/v2'); }
}

// ---------- TOTP ----------
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function base32Encode(buf) {
  let bits = 0, value = 0, out = '';
  for (const byte of buf) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}
function base32Decode(s) {
  let bits = 0, value = 0;
  const out = [];
  for (const ch of s.replace(/=+$/, '').toUpperCase()) {
    const i = B32.indexOf(ch);
    if (i < 0) continue;
    value = (value << 5) | i; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}
function hotp(secret, counter) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', base32Decode(secret)).update(buf).digest();
  const o = h[h.length - 1] & 15;
  return String(((h.readUInt32BE(o) & 0x7fffffff) % 1000000)).padStart(6, '0');
}
export function totpVerify(secret, code, lastStep = 0) {
  code = String(code || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(code)) return 0;
  const step = Math.floor(Date.now() / 30000);
  for (const s of [step - 1, step, step + 1]) {
    if (s <= lastStep) continue; // one-time use
    const a = Buffer.from(hotp(secret, s)), b = Buffer.from(code);
    if (crypto.timingSafeEqual(a, b)) return s;
  }
  return 0;
}
export const newTotpSecret = () => base32Encode(crypto.randomBytes(20));
