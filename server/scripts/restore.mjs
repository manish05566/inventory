// Restore an encrypted Asset Portal backup (.apbak) into a data directory.
// Usage (portal must be STOPPED):  node scripts/restore.mjs <backup.apbak> [dataDir]
// The passphrase is read from the ASSETPORTAL_BACKUP_PASSPHRASE env var or prompted for.
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import { openBackup } from '../src/security.js';

const [file, dirArg] = process.argv.slice(2);
if (!file) { console.error('Usage: node scripts/restore.mjs <backup.apbak> [dataDir]'); process.exit(2); }
const dataDir = path.resolve(dirArg || path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'data'));

async function ask(q) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((res) => rl.question(q, (a) => { rl.close(); res(a); }));
}
const pass = process.env.ASSETPORTAL_BACKUP_PASSPHRASE || await ask('Backup passphrase: ');
const data = openBackup(fs.readFileSync(file), pass);
fs.mkdirSync(dataDir, { recursive: true });
const db = path.join(dataDir, 'inventory.db');
if (fs.existsSync(db)) {
  const keep = `${db}.before-restore-${Date.now()}`;
  fs.renameSync(db, keep);
  for (const ext of ['-wal', '-shm']) fs.rmSync(db + ext, { force: true });
  console.log(`Existing database moved to ${keep}`);
}
fs.writeFileSync(db, Buffer.from(data.db, 'base64'));
if (data.master_key) fs.writeFileSync(path.join(dataDir, 'master.key'), data.master_key, { mode: 0o600 });
console.log(`Restored backup from ${data.created} (host ${data.host}) into ${dataDir}. Start the portal again.`);
