"""Asset Inventory Agent - entry point.

The same code is built twice:
  * AssetAgentSetup.exe  (single file, requires admin, contains payload.zip)  -> setup wizard / silent install
  * AssetAgent.exe       (installed under Program Files)                      -> Windows service, status, uninstall, CLI

Setup:      AssetAgentSetup.exe                          (wizard)
            AssetAgentSetup.exe /quiet --server URL --key KEY [--pin PIN] [--insecure]   (GPO / Intune / SCCM)
Installed:  AssetAgent.exe                               (status window)
            AssetAgent.exe uninstall [/quiet] [/keepdata]
            AssetAgent.exe status | scan | send | version
"""
import argparse
import base64
import json
import os
import re
import sys
from pathlib import Path

from common import AGENT_VERSION, PRODUCT, attach_console, is_admin, log, run_elevated, setup_logging

SLASH_FLAGS = {"/quiet", "/q", "/s", "/silent", "/update", "/keepdata", "-quiet", "--quiet"}


def is_setup_build():
    return getattr(sys, "frozen", False) and (Path(getattr(sys, "_MEIPASS", "")) / "payload.zip").exists()


def embedded_config():
    """Setup downloaded from the portal is named AssetAgentSetup-<base64url json {s,k,p}>.exe."""
    m = re.search(r"AssetAgent(?:Setup)?[-_]([A-Za-z0-9_-]{16,})", Path(sys.executable).stem)
    if not m:
        return {}
    try:
        t = m.group(1)
        d = json.loads(base64.urlsafe_b64decode(t + "=" * (-len(t) % 4)))
        return {"server": d.get("s"), "key": d.get("k"), "pin": d.get("p"), "embedded": True}
    except Exception:
        return {}


def flags(argv):
    low = [a.lower() for a in argv]
    rest = [a for a in argv if a.lower() not in SLASH_FLAGS]
    return set(low) & SLASH_FLAGS, rest


def setup_main(argv):
    setup_logging("setup")
    sw, rest = flags(argv)
    quiet = bool(sw & {"/quiet", "/q", "/s", "/silent", "-quiet", "--quiet"})
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--server")
    p.add_argument("--key")
    p.add_argument("--pin")
    p.add_argument("--insecure", action="store_true")
    a, _ = p.parse_known_args(rest)
    pre = embedded_config()
    server, key, pin = a.server or pre.get("server"), a.key or pre.get("key"), a.pin or pre.get("pin")
    log.info("Setup %s started (quiet=%s update=%s)", AGENT_VERSION, quiet, "/update" in sw)

    if "/update" in sw:
        from installer import perform_update
        try:
            perform_update(lambda i, t: log.info("update: %s", t))
            return 0
        except Exception:
            log.exception("Update failed")
            return 1

    if quiet:
        if not server or not key:
            log.error("Silent install needs --server and --key")
            return 2
        from installer import perform_install
        try:
            r = perform_install(server, key, pin, a.insecure, lambda i, t: log.info("step %d: %s", i + 1, t))
            log.info("Installed; host %s reporting to %s", r["hostname"], r["server"])
            return 0
        except Exception as e:
            log.exception("Silent install failed: %s", getattr(e, "msg", e))
            return 3

    from common import load_config
    from gui import SetupWizard
    from installer import installed_version
    prefill = dict(pre)
    if not prefill.get("server"):
        old = load_config()
        prefill.update({k: old.get(k) for k in ("server", "key", "insecure") if old.get(k)})
    if a.server:
        prefill.update(server=a.server, key=a.key, insecure=a.insecure)
    return SetupWizard(prefill, upgrade_from=installed_version()).run()


def installed_main(argv):
    cmd = (argv[0].lower().lstrip("/-") if argv else "")
    if cmd == "service":
        from service import dispatch
        return dispatch()
    if cmd == "useragent":
        from useragent import run
        return run()
    if cmd == "uninstall":
        sw, _ = flags(argv[1:])
        quiet = bool(sw & {"/quiet", "/q", "/s", "/silent"})
        if not is_admin():
            return 0 if run_elevated(argv) else 1
        setup_logging("setup")
        if quiet:
            from installer import check_uninstall_code, perform_uninstall
            code = next((a.split("=", 1)[1] for a in argv if a.lower().startswith(("/code=", "--code="))), "")
            if not check_uninstall_code(code):
                log.error("Uninstall refused: uninstall protection is on and the code is missing or wrong (use /code=XXXXXXXX)")
                return 5
            perform_uninstall(purge="/keepdata" not in sw)
            return 0
        from gui import UninstallDialog
        return UninstallDialog().run()
    if not cmd:
        from gui import StatusWindow
        return StatusWindow().run()

    attach_console()
    if cmd == "version":
        print(f"{PRODUCT} {AGENT_VERSION}")
    elif cmd == "scan":
        from collector import collect
        print(json.dumps(collect(), indent=2))
    elif cmd == "monitor-test":
        # Collect one activity sample + screenshot locally and print what WOULD be sent (nothing is uploaded).
        from monitor import Collector, foreground, idle_seconds, wifi_location, grab_screenshot
        proc, title = foreground()
        print(f"Foreground app : {proc}")
        print(f"Window title   : {title}")
        print(f"Idle seconds   : {idle_seconds():.0f}")
        print(f"Location       : {wifi_location() or 'no Wi-Fi'}")
        try:
            img, w, h, mon = grab_screenshot()
            out = os.path.join(os.environ.get("TEMP", "."), "assetagent_monitor_test.jpg")
            open(out, "wb").write(img)
            print(f"Screenshot     : {w}x{h}, {mon} monitor(s), {len(img)} bytes -> {out}")
        except Exception as e:
            print(f"Screenshot     : failed ({e})")
    elif cmd in ("status", "send"):
        if not is_admin():
            print("Run this command from an elevated (Administrator) prompt.")
            return 2
        from common import load_config
        from service import service_state
        cfg = load_config()
        if cmd == "send":
            setup_logging("agent", console=True)
            from runtime import send_inventory
            send_inventory(cfg)
            return 0
        print(f"Version        {AGENT_VERSION}")
        print(f"Service        {service_state() or 'not installed'}")
        print(f"Portal         {cfg.get('server', '-')}")
        print(f"Agent ID       {cfg.get('agent_id', '-')}")
        print(f"Interval       {cfg.get('interval_min', '-')} min")
    else:
        print(__doc__)
        return 2
    return 0


def main():
    argv = sys.argv[1:]
    if is_setup_build() and not (argv and argv[0].lower() == "service"):
        return setup_main(argv)
    return installed_main(argv)


if __name__ == "__main__":
    sys.exit(main() or 0)
