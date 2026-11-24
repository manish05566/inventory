"""The agent's work loop (runs inside the Windows service)."""
import hashlib
import subprocess
import threading
import time

from collector import collect
from common import (AGENT_VERSION, DATA_DIR, DETACHED, HEARTBEAT_SEC, SETUP_NAME, load_config, log, save_config)
from protocol import ApiError, enroll, http, message


def send_inventory(cfg, inv=None):
    inv = inv or collect()
    if not cfg.get("agent_id"):
        enroll(cfg, inv)
        log.info("Enrolled as agent %s", cfg["agent_id"])
    try:
        res = message(cfg, "checkin", inv, timeout=180)
    except ApiError as e:
        if e.status != 401 or not cfg.get("key"):
            raise
        log.warning("Portal no longer recognises this agent (%s) - re-enrolling", e.msg)
        for k in ("agent_id", "secret"):
            cfg.pop(k, None)
        enroll(cfg, inv)
        res = message(cfg, "checkin", inv, timeout=180)
    cfg["interval_min"] = res.get("interval_min", cfg.get("interval_min", 60))
    cfg["last_inventory"] = time.time()
    save_config(cfg)
    log.info("Inventory sent (%d software, %d disks, %d NICs)", len(inv["software"]), len(inv["disks"]), len(inv["nics"]))
    return res


def _version(v):
    try:
        return tuple(int(x) for x in str(v).split("."))
    except ValueError:
        return (0,)


def maybe_update(cfg, info):
    """Download a newer setup over the encrypted channel's hash and run it silently (it restarts the service)."""
    if not info or _version(info.get("version")) <= _version(AGENT_VERSION):
        return False
    log.info("Updating agent %s -> %s", AGENT_VERSION, info["version"])
    data = http(cfg, "GET", info["url"], raw=True, timeout=600)
    if hashlib.sha256(data).hexdigest() != info.get("sha256"):
        log.error("Update rejected: checksum mismatch")
        return False
    target = DATA_DIR / "update" / SETUP_NAME
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    subprocess.Popen([str(target), "/quiet", "/update"], creationflags=DETACHED, close_fds=True)
    return True


def run_loop(stop: threading.Event):
    cfg = load_config()
    if not cfg.get("server"):
        log.error("Agent is not configured - reinstall with the setup program.")
        stop.wait()
        return
    log.info("%s service started", AGENT_VERSION)
    backoff = 60
    while not stop.is_set():
        wait = HEARTBEAT_SEC
        try:
            due = time.time() - cfg.get("last_inventory", 0) >= cfg.get("interval_min", 60) * 60
            hb = {}
            if cfg.get("agent_id"):
                try:
                    hb = message(cfg, "heartbeat", {"agent_version": AGENT_VERSION}, timeout=30)
                    cfg["interval_min"] = hb.get("interval_min", cfg.get("interval_min", 60))
                except ApiError as e:
                    if e.status != 401:
                        raise
                    due = True  # send_inventory re-enrolls
            if due or hb.get("scan_now"):
                res = send_inventory(cfg)
                hb["update"] = res.get("update") or hb.get("update")
                hb["monitoring"] = res.get("monitoring") or hb.get("monitoring")
                hb["uninstall"] = res.get("uninstall") or hb.get("uninstall")
            # Cache the uninstall-protection policy (a salted hash; the code itself never reaches the device).
            pol = hb.get("uninstall")
            if pol is not None:
                want = pol.get("hash") if pol.get("required") else None
                if cfg.get("uninstall_hash") != want:
                    cfg["uninstall_hash"] = want
                    save_config(cfg)
            # Keep the per-user monitoring helper running in the interactive session when enabled.
            try:
                from usersession import ensure as ensure_monitor
                ensure_monitor(bool((hb.get("monitoring") or {}).get("enabled")))
            except Exception as e:
                log.debug("monitor helper management skipped: %s", e)
            if maybe_update(cfg, hb.get("update")):
                stop.wait(600)  # the setup stops this service shortly
            backoff = 60
        except Exception as e:  # never die - log and back off
            log.warning("Cycle failed: %s (retrying in %ss)", e, backoff)
            wait = backoff
            backoff = min(backoff * 2, 900)
            cfg = load_config() or cfg
        stop.wait(wait)
    log.info("Service stopping")
