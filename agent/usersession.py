"""Launch the monitoring helper in the interactive user session from the SYSTEM service.

A session-0 service cannot capture the user's desktop, so it starts `AssetAgent.exe useragent` in the
active console session with the user's own token (CreateProcessAsUser). Credentials are passed through the
(in-memory) environment block, never the command line or disk.
"""
import os
import sys

from common import EXE_NAME, INSTALL_DIR, load_config, log

NO_SESSION = 0xFFFFFFFF


def active_session():
    import win32ts
    sid = win32ts.WTSGetActiveConsoleSessionId()
    if sid == NO_SESSION:
        return None
    # Only launch when a real user is logged on and unlocked-ish (has a username).
    try:
        user = win32ts.WTSQuerySessionInformation(win32ts.WTS_CURRENT_SERVER_HANDLE, sid, win32ts.WTSUserName)
    except Exception:
        user = None
    return sid if user else None


def is_running_in(sid):
    """True if our user helper is already running in session `sid`."""
    import win32ts
    try:
        procs = win32ts.WTSEnumerateProcesses(win32ts.WTS_CURRENT_SERVER_HANDLE, 1, 0)
    except Exception:
        return False
    target = EXE_NAME.lower()
    for (psid, _pid, name, _sid) in procs:
        if psid == sid and name and name.lower() == target:
            # the service itself runs in session 0, so any match in the user session is the helper
            return True
    return False


def launch(sid, cfg):
    import win32con
    import win32process
    import win32profile
    import win32security
    import win32ts
    exe = INSTALL_DIR / EXE_NAME
    if not exe.exists():
        exe = os.path.join(os.path.dirname(sys.executable), EXE_NAME)
    token = win32ts.WTSQueryUserToken(sid)
    try:
        env = win32profile.CreateEnvironmentBlock(token, False)
        env = dict(env) if not isinstance(env, dict) else env
        env["ASSETAGENT_SRV"] = cfg.get("server", "")
        env["ASSETAGENT_AID"] = cfg.get("agent_id", "")
        env["ASSETAGENT_SEC"] = cfg.get("secret", "")
        env["ASSETAGENT_PIN"] = cfg.get("pin") or ""
        env["ASSETAGENT_INSECURE"] = "1" if cfg.get("insecure") else "0"
        si = win32process.STARTUPINFO()
        si.lpDesktop = "winsta0\\default"
        flags = win32con.CREATE_UNICODE_ENVIRONMENT | win32con.CREATE_NO_WINDOW | 0x00000008  # DETACHED_PROCESS
        hp, ht, pid, tid = win32process.CreateProcessAsUser(
            token, str(exe), f'"{exe}" useragent', None, None, False, flags, env, str(INSTALL_DIR), si)
        import win32api
        win32api.CloseHandle(hp)
        win32api.CloseHandle(ht)
        log.info("Launched monitoring helper in session %s (pid %s)", sid, pid)
        return True
    finally:
        import win32api
        win32api.CloseHandle(token)


def ensure(enabled):
    """Called each service cycle: keep the helper running in the active session when monitoring is on."""
    try:
        sid = active_session()
        if not enabled or sid is None:
            return
        if is_running_in(sid):
            return
        cfg = load_config()
        if cfg.get("agent_id") and cfg.get("secret"):
            launch(sid, cfg)
    except Exception as e:
        log.warning("Could not manage monitoring helper: %s", e)
