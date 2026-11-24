# Asset Portal — IT asset management with an encrypted Windows agent

Install the agent on a Windows PC with a standard setup wizard. The PC then appears in the portal and keeps its
hardware, software, patches, users and security posture up to date automatically, over an end-to-end encrypted
channel.

```
inventory/
├── server/                 Portal (Node.js ≥ 22.13, zero npm dependencies, SQLite built in)
│   ├── server.js           entry point (HTTP/HTTPS, security headers, sessions)
│   ├── src/                api, crypto (E2E + at-rest + TOTP), inventory/diffing, alerts, discovery, db
│   ├── public/             web UI (single-page app, no build step)
│   ├── scripts/new-cert.ps1  creates an HTTPS certificate (PFX)
│   ├── downloads/          AssetAgentSetup.exe + agent-version.txt (served to clients)
│   └── data/               inventory.db + master.key (created on first start, BACK UP BOTH)
└── agent/
    ├── agent.py            entry point (setup / service / status / uninstall / CLI)
    ├── gui.py              setup wizard, uninstaller and status window
    ├── installer.py        install/upgrade/uninstall engine (service, Apps & Features)
    ├── service.py          Windows service host
    ├── runtime.py          heartbeat / inventory / self-update loop
    ├── protocol.py         encrypted protocol (X25519 + AES-256-GCM)
    ├── collector.py        inventory collection (CIM/WMI + registry)
    ├── common.py           constants, logging, DPAPI-encrypted config
    ├── make_assets.py      generates the icon & logos
    └── build.ps1           builds the installer and publishes it to server/downloads
```

## 1. Run the portal

```powershell
cd inventory\server
npm start
```

Open `http://<server-ip>:8080` and sign in as `admin` / `admin`. You must change the password at first sign-in;
then enable two-factor under *Security*. In **Settings**, set the *Public portal URL* to the address PCs use to
reach the server, and allow the port in the server firewall:

```powershell
New-NetFirewallRule -DisplayName "Asset Portal" -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow
```

**HTTPS (recommended):** `powershell -ExecutionPolicy Bypass -File scripts\new-cert.ps1 -Names assets.company.local,192.168.1.10`
prints the env vars to start with (`TLS_PFX`, `TLS_PFX_PASSPHRASE`, `PORT=8443`). A certificate from your internal CA works the same way.

| Env var | Default | Purpose |
|---|---|---|
| `PORT` / `HOST` | `8080` / `0.0.0.0` | listen address |
| `DATA_DIR` | `server/data` | database + master key location |
| `TLS_PFX` + `TLS_PFX_PASSPHRASE` (or `TLS_CERT` + `TLS_KEY`) | – | serve HTTPS |
| `MASTER_KEY` | `data/master.key` | 32-byte base64 key for at-rest encryption (e.g. from a secret store) |
| `ADMIN_PASSWORD` | `admin` | initial admin password on first start |
| `TRUST_PROXY=1` | off | behind a reverse proxy: trust `X-Forwarded-For/Proto` |

Run it permanently with NSSM (`nssm install AssetPortal "C:\Program Files\nodejs\node.exe" server.js`) or PM2.

## 2. Build the agent installer

```powershell
cd inventory\agent
powershell -ExecutionPolicy Bypass -File build.ps1                 # unsigned
powershell -ExecutionPolicy Bypass -File build.ps1 -CertThumbprint <code-signing cert thumbprint>   # signed
```

This produces `AssetAgentSetup.exe` (icon, version info, UAC prompt) and publishes it to the portal.
Bump `AGENT_VERSION` in `common.py` and rebuild to roll out an update: every agent downloads it over the encrypted
channel, verifies its SHA-256 and upgrades itself silently.

> Without a code-signing certificate, Windows SmartScreen shows "Unknown publisher". For enterprise rollout, sign
> with your organization's certificate (or deploy through Intune/GPO, which bypasses SmartScreen).

## 3. Install on PCs

**Interactive:** in the portal open *Agents & deployment*, click **Download installer** and run it on the PC.
The installer is pre-configured with the portal URL and key, and has the portal's identity pinned. The user approves
the UAC prompt and clicks *Next* and then *Install*. The wizard verifies the portal, registers the PC, sends the
first inventory, then installs and starts the service, so a wrong URL or key leaves nothing behind.

**Silent (GPO / Intune Win32 app / SCCM / PDQ):**
```
AssetAgentSetup.exe /quiet --server https://assets.company.local --key <ENROLLMENT_KEY>
```
Exit code 0 means success. The log is in `C:\ProgramData\AssetAgent\logs\setup.log`.

**Uninstall:** use *Settings › Apps › Asset Inventory Agent*, or run silently:
`"C:\Program Files\AssetAgent\AssetAgent.exe" uninstall /quiet`

What gets installed:
- `C:\Program Files\AssetAgent\` holds the program files.
- The **Asset Inventory Agent** Windows service runs as LocalSystem with delayed automatic start, and restarts on
  failure.
- An Apps & Features entry provides uninstall.
- `C:\ProgramData\AssetAgent\` holds the encrypted config and the logs. It is accessible to SYSTEM and Administrators
  only.

The agent sends a heartbeat every minute (online status, on-demand rescan, updates). It sends full inventory every
*N* minutes (Settings, default 60). Re-installs match the existing asset by SMBIOS UUID, then serial, then
hostname+MAC.

## Security model

| Area | Protection |
|---|---|
| Agent ↔ portal | End-to-end encryption independent of TLS. Enrollment does an X25519 key exchange with the portal's identity key, which is **pinned** in downloaded installers (otherwise shown as a fingerprint to verify). After that, every message is AES-256-GCM under a per-agent secret, bound to agent id, message type and timestamp, with a 5-minute freshness window and replay protection. Payloads are gzip-compressed. |
| Agent at rest | Config (agent secret, enrollment key) is encrypted with **Windows DPAPI** (machine scope) in a folder restricted to SYSTEM and Administrators. |
| Updates | The SHA-256 of the installer comes over the encrypted channel and is verified before the installer runs. |
| Portal at rest | Agent secrets, the server private key, license keys and 2FA secrets are encrypted with AES-256-GCM under the master key (`data/master.key` or `MASTER_KEY`). Enable BitLocker on the server for full-disk protection. |
| Sign-in | scrypt password hashing. Password policy: 10+ characters with letters and numbers. **TOTP two-factor** (one-time codes, optionally required for admins). Lockout after 5 failures for 15 minutes. Idle timeout (30 min) and absolute session limit (12 h). Session list with "sign out others". |
| Web | Strict CSP, `X-Frame-Options: DENY`, `SameSite=Strict` HttpOnly cookies (Secure on HTTPS), CSRF header check, HSTS on HTTPS, no-referrer. |
| Accountability | Audit log of sign-ins (including failures and lockouts), enrollments and every change. Roles: viewer, technician, administrator. |

## Inventory & users (Snipe-IT-style)

| Feature | How it works |
|---|---|
| **Roles** | *Self-service* (own assets only), *Viewer* (read-only), *Technician* (manage inventory), *Administrator* (everything). |
| **Permission groups** | *Administration › Permission groups*. Tick rights per area (view / edit / delete / check out / audit / import / monitoring). A user placed in a group gets exactly those rights instead of their role defaults. Administration itself can't be granted by a group, so admins can never be locked out by one. Every one of the 121 API routes is mapped to a permission and enforced on the server. |
| **Self-service login** | On a person's page, click **Enable self-service login**, or create a user with the *Self-service* role linked to a person. Employees sign in and see only *My assets*: assigned equipment, accessories they hold, and history. |
| **Acceptance (EULA)** | *Settings › Require users to accept assigned assets*. New assignments show as *Awaiting acceptance* until the employee signs by typing their name. Declines raise an alert; accepted/declined status and the signature are stored on the check-out. |
| **Assign / check out** | To a **person** or a **location**, with due date and notes; **bulk check-out** from the Assets list; check-in records condition and new status. |
| **Accessories & stock** | *Inventory › Accessories & stock*. Quantity-tracked accessories (returned), consumables (issued and used up) and components. Check out / check in, restock / write-off, minimum-quantity alerts, full movement history. |
| **Physical audit** | **Audit** on an asset (or bulk from the list) records date, location and notes, and schedules the next audit (*Settings › audit interval*). Overdue audits raise alerts and appear in *Reports › Physical audit due*. |
| **Import centre** | *Inventory › Bulk import*. Works like Snipe-IT: **Select file…** uploads CSVs (kept encrypted on the server, re-processable, deletable). **Process** opens the mapping panel: import type, *Update existing values*, *Backup before importing*, date format, then CSV header → import field → sample value. Use **Preview (dry run)** before **Process import**. Types: **Assets, People, Users (with login), Accessories, Consumables, Components, Licenses, Locations**. Asset fields include Company, Model name/number, Category, Model notes, Order number, Supplier, Status (Stock / Deployed / Ready to Deploy / Broken / Archived / Lost…), Purchase date & cost, Warranty, EOL, **Checkout type + Checked out to (username / first / last / email) + Checkout location** (creates real check-outs), and custom fields (pick *+ New custom field* to create one from a column, e.g. "Configuration"). Dates like `11-Sep-26`, `13/05/2026` or Excel numbers, and amounts like `4,50,000`, `₹58,500` or `1.2 lakh`, are understood. Missing companies, models, manufacturers, categories, suppliers, locations and people are created automatically. User imports create self-service logins for *Activated* rows and show the generated passwords once (downloadable CSV). Re-importing the same file updates records (matched by asset tag/serial, email/employee no./username, name) and never duplicates check-outs. Pre-import backups go to `data\backups` (last 10 kept). |
| **Catalog** | *Management › Catalog*: **Asset models** (manufacturer, category, model number, default type, EOL months), **Categories** (for assets, accessories, consumables, components, licenses), **Manufacturers** (support contacts), **Suppliers**, **Companies**. Assets link to model / company / supplier; renaming a model updates all its assets; counts link to filtered asset lists. |
| **Locations map** | *Inventory › Locations map* (OpenStreetMap). Click **Place**, then click the map to pin a site; markers scale with asset count; popups link to that site's assets. |
| **Reports** | New: *Stock levels*, *Physical audit due*, *Assignments awaiting acceptance*. |

## Security center (Administration › Security center)

| Control | What it does |
|---|---|
| **Security score** | Live posture checks: HTTPS, admin 2FA, 2FA policy, audit integrity, IP allowlist, idle timeout, brute-force activity. |
| **IP allowlist** | Restrict the portal to office/VPN ranges (CIDR). Agents and installers are always allowed. Saving a list that would lock out your own address is refused. |
| **Password expiry / 2FA policy / session limits** | Force periodic password changes, require 2FA for admins, set idle and absolute session lifetimes. |
| **Rate limiting** | Per-IP limits on sign-in (20/min), enrollment (30/min) and the API (agents get a high budget for NAT). |
| **Tamper-evident audit log** | Every entry is SHA-256-chained to the previous one; *Verify now* detects edits or deletions made outside the portal. CSV export includes the hashes. |
| **API tokens** | `Authorization: Bearer ap_…` for Power BI, SIEM, ServiceNow or scripts. Read-only or read/write, optional expiry, shown once, stored hashed, never admin-capable, last use tracked. |
| **Alert notifications** | New alerts go to Microsoft Teams, Slack, or a generic JSON webhook signed with `X-AssetPortal-Signature: sha256=HMAC(timestamp.body)`. |
| **Agent uninstall protection** | Users need a portal-issued code to remove the agent (`uninstall /quiet /code=XXXXXXXX`). Devices only ever receive a salted hash of the code. |
| **Encrypted backup** | Downloads the database plus master key, encrypted with your passphrase (scrypt + AES-256-GCM). Restore with the portal stopped: `node scripts\restore.mjs backup.apbak [dataDir]`. |

## Productivity

- **Command palette:** `Ctrl+K` searches pages, actions, assets, people and software.
- **Shortcuts:** `/` jumps to search, `g` then `d`/`a`/`s`/`l`/`m`/`r`/`c`/`p` navigates, `n` creates a new asset, `?` shows help.
- **Assets table:** choose your own columns and save filter combinations as named views (remembered per user in the browser).
- **Layout:** collapsible sidebar, a quick **New** menu, and loading skeletons.
- **Check-out / check-in:** lend equipment to a person with a due date. Overdue items raise alerts and appear on the dashboard and in the *Overdue check-outs* report. Full history is kept per asset.
- **Reports:** new *Patch compliance* report (devices without a Windows update in N days) and *Overdue check-outs* report.

## Activity monitoring (optional, off by default)

On organization‑managed devices, the agent can record **active application and window titles**, **periodic
screenshots** and **coarse Wi‑Fi/network location**. It is designed for transparent workplace monitoring, not
covert surveillance:

- **Off by default.** An administrator enables it under *Activity & screens* and must tick an acknowledgment that
  the devices are organization‑managed and users are informed, as required by law.
- **Transparent on the device.** The capture runs as a per‑user helper that shows a **notification‑area (tray)
  icon** and a startup notice; a right‑click menu tells the user exactly what is recorded. The notice text is
  configurable in the portal.
- **No keystrokes or passwords.** Only the foreground app and window title are recorded; window titles that look
  like credential/password prompts are redacted to `[hidden – sensitive window]`.
- **Encrypted & retention‑limited.** Activity and screenshots travel over the same end‑to‑end encrypted channel;
  screenshots are encrypted at rest with the master key and auto‑deleted after the retention period (default 30
  days). Monitoring data is visible only to technicians and administrators, and every screenshot view is audited.

**How it works technically:** a session‑0 Windows service cannot see the user's desktop, so the service launches
`AssetAgent.exe useragent` in the active console session (`CreateProcessAsUser`), passing credentials only through
the in‑memory environment. The helper samples the foreground window and idle time, captures screenshots on the
configured interval (or on demand from the portal), reports coarse location, and uploads batches over the encrypted
channel. Configure everything under **Activity & screens**; view per‑device detail on an asset's **Activity** tab
(app breakdown, category chart, screenshot gallery, location history and timeline).

> **Your responsibility:** employee monitoring is regulated and varies by country/region. Enable it only on
> devices you own or manage, with the disclosure, notice and consent your jurisdiction requires. The acknowledgment
> in the portal and the on‑device notice help, but do not replace your own legal/HR review.

## Features

- **Inventory:** model, serial, UUID, chassis, CPU, RAM modules, volumes, SSD/HDD, GPUs, monitors, BIOS, board, TPM,
  NICs, OS build, last boot, logged-on user, antivirus, BitLocker, installed software (machine and per-user), patches.
- **Change tracking:** hardware, OS, user and security changes, plus software installed, updated or removed.
- **Assets:** manual, CSV import, discovery or agent. Lifecycle, assignment, financials, warranty, custom fields,
  notes and maintenance, relations, bulk edit, export, QR labels.
- **Software & licenses:** catalog, authorized/prohibited classification, automatic license compliance.
- **Contracts, network discovery, alerts** (raised and resolved automatically), and **20 reports** with CSV export.
