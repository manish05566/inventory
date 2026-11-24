import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { Db, DEFAULT_SETTINGS } from './src/db.js';
import { HttpError, json, readBody, serveStatic, parseCookies } from './src/web.js';
import { buildApi, hashPassword } from './src/api.js';
import { evaluateAlerts, sha256 } from './src/inventory.js';
import { DiscoveryService } from './src/discovery.js';
import { Crypto } from './src/crypto.js';
import { Monitoring } from './src/monitoring.js';
import { RateLimiter, parseAllowlist, ipAllowed, verifyToken } from './src/security.js';
import { sendWebhook } from './src/notify.js';
import { effectivePerms, requiredPerm } from './src/perms.js';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(ROOT, 'data'));
const DOWNLOAD_DIR = path.resolve(process.env.DOWNLOAD_DIR || path.join(ROOT, 'downloads'));
const PUBLIC_DIR = path.join(ROOT, 'public');
const TLS = process.env.TLS_PFX
  ? { pfx: fs.readFileSync(process.env.TLS_PFX), passphrase: process.env.TLS_PFX_PASSPHRASE || '' }
  : process.env.TLS_CERT && process.env.TLS_KEY
    ? { cert: fs.readFileSync(process.env.TLS_CERT), key: fs.readFileSync(process.env.TLS_KEY) } : null;
const TRUST_PROXY = process.env.TRUST_PROXY === '1';

fs.mkdirSync(DOWNLOAD_DIR, { recursive: true });
const db = new Db(path.join(DATA_DIR, 'inventory.db'));

// ---------- first-run bootstrap ----------
for (const [k, v] of Object.entries(DEFAULT_SETTINGS)) if (db.setting(k) === null) db.setSetting(k, v);
if (!db.setting('enrollment_key')) db.setSetting('enrollment_key', crypto.randomBytes(16).toString('hex'));
const vault = new Crypto(db, DATA_DIR);
// Encrypt any license keys stored before at-rest encryption existed.
for (const l of db.all("SELECT id, license_key FROM licenses WHERE license_key IS NOT NULL AND license_key <> '' AND license_key NOT LIKE 'enc:v1:%'")) {
  db.run('UPDATE licenses SET license_key=? WHERE id=?', vault.encrypt(l.license_key), l.id);
}
if (!db.get('SELECT id FROM users LIMIT 1')) {
  const pw = process.env.ADMIN_PASSWORD || 'admin';
  db.insert('users', { username: 'admin', name: 'Administrator', role: 'admin', pass_hash: hashPassword(pw), must_change: 1 });
  console.log(`[init] Created user "admin" with password "${pw}" — you will be asked to change it at first login.`);
}

// ---------- alerts scheduler ----------
let alertTimer = null;
const runAlerts = () => {
  try {
    const created = evaluateAlerts(db);
    if (created?.length) sendWebhook(db, vault, created).catch((e) => console.error('[webhook]', e.message));
  } catch (e) { console.error('[alerts]', e); }
};
const scheduleAlerts = () => { if (!alertTimer) alertTimer = setTimeout(() => { alertTimer = null; runAlerts(); }, 3000); };
runAlerts();
setInterval(runAlerts, 10 * 60 * 1000).unref();
setInterval(() => db.run('DELETE FROM sessions WHERE expires_at < ?', Date.now()), 3600 * 1000).unref();

const discovery = new DiscoveryService(db);
const monitoring = new Monitoring(db, vault, path.join(DATA_DIR, 'screenshots'));
const runRetention = () => { try { monitoring.retention(); } catch (e) { console.error('[retention]', e); } };
runRetention();
setInterval(runRetention, 6 * 3600 * 1000).unref();
const { router, ROLES } = buildApi({ db, vault, monitoring, discovery, downloadDir: DOWNLOAD_DIR, dataDir: DATA_DIR, scheduleAlerts });

const CSP = ["default-src 'self'", "script-src 'self' https://cdnjs.cloudflare.com", "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
  "img-src 'self' data: blob: https://*.tile.openstreetmap.org https://tile.openstreetmap.org", "connect-src 'self'", "font-src 'self' data:", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'", "object-src 'none'"].join('; ');
function securityHeaders(res, secure) {
  res.setHeader('Content-Security-Policy', CSP);
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  if (secure) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
}

const limiter = new RateLimiter();
let allowCache = { raw: null, rules: [] };
function allowRules() {
  const raw = db.setting('portal_ip_allowlist', '');
  if (raw !== allowCache.raw) { try { allowCache = { raw, rules: parseAllowlist(raw) }; } catch { allowCache = { raw, rules: [] }; } }
  return allowCache.rules;
}

function clientIp(req) {
  if (TRUST_PROXY && req.headers['x-forwarded-for']) return String(req.headers['x-forwarded-for']).split(',')[0].trim();
  return (req.socket.remoteAddress || '').replace(/^::ffff:/, '');
}

async function handle(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const secure = !!TLS || (TRUST_PROXY && req.headers['x-forwarded-proto'] === 'https');
  const origin = `${secure ? 'https' : 'http'}://${req.headers.host || `localhost:${PORT}`}`;
  securityHeaders(res, secure);
  const m = router.match(req.method, url.pathname);
  if (!m) {
    if (url.pathname.startsWith('/api/')) return json(res, 404, { error: 'Not found' });
    if (req.method !== 'GET' && req.method !== 'HEAD') return json(res, 405, { error: 'Method not allowed' });
    return serveStatic(req, res, PUBLIC_DIR, url.pathname);
  }
  const { route, params } = m;
  const role = route.meta.role;
  const ip = clientIp(req);
  const isAgent = url.pathname.startsWith('/api/agent/') || url.pathname.startsWith('/download/');
  // Rate limits (per client IP). Agents are often behind NAT, so they get a much higher budget.
  if (url.pathname === '/api/agent/v2/enroll' && !limiter.hit(`enroll:${ip}`, 30)) throw new HttpError(429, 'Too many enrollments from this address');
  if (url.pathname === '/api/login' && !limiter.hit(`login:${ip}`, 20)) throw new HttpError(429, 'Too many sign-in attempts. Wait a minute.');
  if (!limiter.hit(`${isAgent ? 'agent' : 'api'}:${ip}`, isAgent ? 20000 : 1500)) throw new HttpError(429, 'Rate limit exceeded');
  // Portal IP allowlist (agents and installers are exempt so devices can always report).
  if (!isAgent && !ipAllowed(ip, allowRules())) throw new HttpError(403, 'Access from your network is not allowed');
  const sid = parseCookies(req.headers.cookie).sid;
  let user = null;
  if (role !== 'public' && role !== 'agent') {
    const tok = !sid && String(req.headers.authorization || '').startsWith('Bearer ap_') ? verifyToken(db, req.headers.authorization) : null;
    if (tok) {
      // API token: acts with its own role (never admin), no CSRF header needed, cannot touch /api/me.
      if (url.pathname.startsWith('/api/me')) throw new HttpError(403, 'Not available to API tokens');
      db.run('UPDATE api_tokens SET last_used_at=?, last_ip=? WHERE id=?', new Date().toISOString(), ip, tok.id);
      user = { id: 0, username: `token:${tok.name}`, role: tok.role, must_change: 0, totp_enabled: 1, viaToken: true };
    } else if (sid) {
      const idleMs = (Number(db.setting('session_idle_min', 30)) || 30) * 60000;
      user = db.get('SELECT u.*, s.last_seen AS s_last FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires_at > ?', sha256(sid), Date.now());
      if (user && user.s_last && Date.now() - user.s_last > idleMs) {
        db.run('DELETE FROM sessions WHERE token=?', sha256(sid));
        user = null;
      } else if (user && !(url.pathname === '/api/alerts' && req.headers['x-background'] === '1')) {
        db.run('UPDATE sessions SET last_seen=? WHERE token=?', Date.now(), sha256(sid));
      }
    }
    if (!user) throw new HttpError(401, 'Not logged in');
    user._ip = ip;
    user._perms = effectivePerms(db, user);
    const need = requiredPerm(req.method, url.pathname, role);
    if (need && !user._perms.includes(need)) throw new HttpError(403, `You do not have permission to do this (${need})`);
    if (user.role === 'user' && need) throw new HttpError(403, 'Self-service accounts can only use My assets');
    // CSRF guard: state-changing requests from the browser must carry this custom header.
    if (!user.viaToken && req.method !== 'GET' && req.headers['x-requested-with'] !== 'fetch') throw new HttpError(403, 'Missing request header');
    const maxAge = Number(db.setting('password_max_age_days', 0)) || 0;
    if (!user.viaToken && maxAge && user.password_changed_at && Date.now() - Date.parse(user.password_changed_at) > maxAge * 86400000) user.must_change = 1;
    if (user.must_change && req.method !== 'GET' && !['/api/me/password', '/api/logout'].includes(url.pathname)) {
      throw new HttpError(403, 'Please change your password first');
    }
    if (user.role === 'admin' && !user.totp_enabled && db.setting('require_2fa_admins') === '1' && req.method !== 'GET'
      && !url.pathname.startsWith('/api/me/') && url.pathname !== '/api/logout') {
      throw new HttpError(403, 'Administrators must enable two-factor authentication first');
    }
  }
  const body = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) ? await readBody(req) : {};
  const query = Object.fromEntries(url.searchParams);
  const out = await route.handler({ req, res, params, query, body, user, sid, ip, origin, secure });
  if (out !== undefined && !res.headersSent) json(res, 200, out);
}

const onRequest = (req, res) => {
  handle(req, res).catch((e) => {
    const status = e instanceof HttpError ? e.status : 500;
    if (status === 500) console.error(`[error] ${req.method} ${req.url}`, e);
    json(res, status, { error: status === 500 ? 'Internal server error' : e.message });
  });
};

const server = TLS ? https.createServer(TLS, onRequest) : http.createServer(onRequest);
server.requestTimeout = 120000;
server.listen(PORT, HOST, () => {
  console.log(`Asset portal listening on ${TLS ? 'https' : 'http'}://${HOST}:${PORT}`);
  console.log(`Data: ${DATA_DIR}   Agent downloads: ${DOWNLOAD_DIR}`);
});
const shutdown = () => { server.close(); db.db.close(); process.exit(0); };
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
