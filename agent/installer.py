"""Install / upgrade / uninstall engine shared by the setup wizard and the silent (/quiet) mode."""
import datetime as dt
import os
import shutil
import subprocess
import sys
import tempfile
import time
import winreg
import zipfile
from pathlib import Path

import win32service
import win32serviceutil

from collector import collect
from common import (AGENT_VERSION, CREATE_NO_WINDOW, DATA_DIR, DETACHED, EXE_NAME, INSTALL_DIR, LOG_DIR, PRODUCT, PUBLISHER,
                    SERVICE_NAME, UNINSTALL_KEY, load_config, log, save_config, secure_dir)
from protocol import enroll, fetch_identity, message
from service import AgentService, service_state


class InstallError(Exception):
    pass


def installed_version():
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, UNINSTALL_KEY, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            return winreg.QueryValueEx(k, "DisplayVersion")[0]
    except OSError:
        return None


def registry_value(name):
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, UNINSTALL_KEY, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


# ------------------------------------------------------------------ service control
def stop_service(timeout=45):
    if service_state() in (None, "stopped"):
        return
    try:
        win32serviceutil.StopService(SERVICE_NAME)
    except Exception:
        pass
    end = time.time() + timeout
    while time.time() < end and service_state() not in (None, "stopped"):
        time.sleep(0.5)
    subprocess.run(["taskkill", "/F", "/IM", EXE_NAME, "/FI", f"PID ne {os.getpid()}"], capture_output=True, creationflags=CREATE_NO_WINDOW)


def ensure_service(exe: Path):
    binpath = f'"{exe}" service'
    scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
    try:
        try:
            h = win32service.OpenService(scm, SERVICE_NAME, win32service.SERVICE_ALL_ACCESS)
            win32service.ChangeServiceConfig(h, win32service.SERVICE_WIN32_OWN_PROCESS, win32service.SERVICE_AUTO_START,
                                             win32service.SERVICE_ERROR_NORMAL, binpath, None, 0, None, None, None, PRODUCT)
        except win32service.error:
            h = win32service.CreateService(scm, SERVICE_NAME, PRODUCT, win32service.SERVICE_ALL_ACCESS,
                                           win32service.SERVICE_WIN32_OWN_PROCESS, win32service.SERVICE_AUTO_START,
                                           win32service.SERVICE_ERROR_NORMAL, binpath, None, 0, None, None, None)
        win32service.ChangeServiceConfig2(h, win32service.SERVICE_CONFIG_DESCRIPTION, AgentService._svc_description_)
        try:
            win32service.ChangeServiceConfig2(h, win32service.SERVICE_CONFIG_DELAYED_AUTO_START_INFO, True)
        except Exception:
            pass
        win32service.CloseServiceHandle(h)
    finally:
        win32service.CloseServiceHandle(scm)
    # Restart automatically if the process ever dies.
    subprocess.run(["sc.exe", "failure", SERVICE_NAME, "reset=", "86400", "actions=", "restart/30000/restart/60000/restart/300000"],
                   capture_output=True, creationflags=CREATE_NO_WINDOW)


def start_service(timeout=60):
    win32serviceutil.StartService(SERVICE_NAME)
    end = time.time() + timeout
    while time.time() < end:
        st = service_state()
        if st == "running":
            return
        if st == "stopped":
            break
        time.sleep(0.5)
    raise InstallError(f"The service did not start (state: {service_state()}). See {LOG_DIR / 'agent.log'}")


def remove_service():
    stop_service()
    try:
        win32serviceutil.RemoveService(SERVICE_NAME)
    except Exception:
        pass


# ------------------------------------------------------------------ files & registration
def install_files():
    payload = Path(getattr(sys, "_MEIPASS", ".")) / "payload.zip"
    if not payload.exists():
        raise InstallError("Setup package is incomplete (payload missing)")
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    last = None
    for _ in range(20):  # files may stay locked for a moment after the service stops
        try:
            for child in INSTALL_DIR.iterdir():
                shutil.rmtree(child) if child.is_dir() else child.unlink()
            with zipfile.ZipFile(payload) as z:
                z.extractall(INSTALL_DIR)
            return INSTALL_DIR / EXE_NAME
        except PermissionError as e:
            last = e
            time.sleep(1)
    raise InstallError(f"Could not replace program files: {last}")


def register_app(server):
    exe = INSTALL_DIR / EXE_NAME
    size_kb = sum(f.stat().st_size for f in INSTALL_DIR.rglob("*") if f.is_file()) // 1024
    with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, UNINSTALL_KEY, 0, winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY) as k:
        for name, typ, val in [
            ("DisplayName", winreg.REG_SZ, PRODUCT), ("DisplayVersion", winreg.REG_SZ, AGENT_VERSION),
            ("Publisher", winreg.REG_SZ, PUBLISHER), ("DisplayIcon", winreg.REG_SZ, f"{exe},0"),
            ("InstallLocation", winreg.REG_SZ, str(INSTALL_DIR)), ("UninstallString", winreg.REG_SZ, f'"{exe}" uninstall'),
            ("QuietUninstallString", winreg.REG_SZ, f'"{exe}" uninstall /quiet'), ("URLInfoAbout", winreg.REG_SZ, server or ""),
            ("PortalUrl", winreg.REG_SZ, server or ""), ("InstallDate", winreg.REG_SZ, dt.date.today().strftime("%Y%m%d")),
            ("EstimatedSize", winreg.REG_DWORD, size_kb), ("NoModify", winreg.REG_DWORD, 1), ("NoRepair", winreg.REG_DWORD, 1),
        ]:
            winreg.SetValueEx(k, name, 0, typ, val)


# ------------------------------------------------------------------ install
INSTALL_STEPS = [
    "Verifying the portal's identity",
    "Collecting inventory from this computer",
    "Registering with the portal (encrypted)",
    "Sending inventory",
    "Stopping the previous version",
    "Installing program files",
    "Installing the Windows service",
    "Starting the service",
    "Registering with Windows",
]
UPDATE_STEPS = INSTALL_STEPS[4:]


def perform_install(server, key, pin=None, insecure=False, report=lambda i, text: None):
    """Full install. Talks to the portal *before* changing the system, so a bad URL/key leaves nothing behind."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    secure_dir(DATA_DIR)
    old = load_config()
    cfg = {"server": server.rstrip("/"), "key": key, "pin": pin, "insecure": bool(insecure)}

    report(0, INSTALL_STEPS[0])
    pub_cfg = dict(cfg)
    pub, fingerprint = fetch_identity(pub_cfg)
    import base64
    cfg["server_pub"] = base64.b64encode(pub).decode()
    same = old.get("agent_id") and old.get("secret") and old.get("server", "").rstrip("/") == cfg["server"] and old.get("server_pub") == cfg["server_pub"]
    if same:  # upgrade/repair: keep the existing identity in the portal
        cfg.update({k: old[k] for k in ("agent_id", "secret", "asset_id", "interval_min", "last_inventory") if k in old})
    log.info("Portal %s identity %s", cfg["server"], fingerprint)

    report(1, INSTALL_STEPS[1])
    inv = collect()

    report(2, INSTALL_STEPS[2])
    if not cfg.get("agent_id"):
        enroll(cfg, inv)
        log.info("Enrolled as agent %s (asset %s)", cfg["agent_id"], cfg.get("asset_id"))

    report(3, INSTALL_STEPS[3])
    res = message(cfg, "checkin", inv, timeout=180)
    cfg["interval_min"] = res.get("interval_min", 60)
    cfg["last_inventory"] = time.time()
    save_config(cfg)

    _install_binaries(cfg["server"], report, offset=4)
    return {"hostname": inv["system"].get("hostname"), "fingerprint": fingerprint, "server": cfg["server"]}


def perform_update(report=lambda i, text: None):
    cfg = load_config()
    if not cfg.get("server"):
        raise InstallError("No existing configuration - run a full install")
    _install_binaries(cfg["server"], report, offset=0)


def _install_binaries(server, report, offset):
    report(offset, INSTALL_STEPS[4])
    stop_service()
    report(offset + 1, INSTALL_STEPS[5])
    exe = install_files()
    report(offset + 2, INSTALL_STEPS[6])
    ensure_service(exe)
    report(offset + 3, INSTALL_STEPS[7])
    start_service()
    report(offset + 4, INSTALL_STEPS[8])
    register_app(server)
    log.info("Installed %s %s", PRODUCT, AGENT_VERSION)


# ------------------------------------------------------------------ uninstall
def uninstall_code_required():
    return bool(load_config().get("uninstall_hash"))


def check_uninstall_code(code):
    """True when uninstall protection is off, or the code matches the portal-issued hash."""
    import hashlib
    cfg = load_config()
    want = cfg.get("uninstall_hash")
    if not want:
        return True
    got = hashlib.sha256(f"{cfg.get('agent_id', '')}:{str(code or '').strip()}".encode()).hexdigest()
    import hmac
    return hmac.compare_digest(got, want)


def perform_uninstall(purge=False):
    remove_service()
    try:
        winreg.DeleteKeyEx(winreg.HKEY_LOCAL_MACHINE, UNINSTALL_KEY, winreg.KEY_WOW64_64KEY, 0)
    except OSError:
        pass
    log.info("Uninstalled (purge=%s)", purge)
    if purge:
        for h in list(log.handlers):  # release the log file so the folder can be deleted
            h.close()
            log.removeHandler(h)
        shutil.rmtree(DATA_DIR, ignore_errors=True)
    running_from_install = Path(sys.executable).resolve().parent == INSTALL_DIR.resolve()
    if running_from_install:  # cannot delete our own exe - let a detached cmd finish the job
        script = Path(tempfile.gettempdir()) / "assetagent_cleanup.cmd"
        script.write_text(f'@echo off\r\nping -n 4 127.0.0.1 >nul\r\nrmdir /s /q "{INSTALL_DIR}"\r\ndel "%~f0"\r\n')
        subprocess.Popen(["cmd.exe", "/c", str(script)], creationflags=DETACHED | CREATE_NO_WINDOW, close_fds=True)
    else:
        shutil.rmtree(INSTALL_DIR, ignore_errors=True)
