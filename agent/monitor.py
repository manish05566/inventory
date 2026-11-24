"""Per-user activity / screenshot / location collector.

Runs as the LOGGED-IN USER (launched by the service in the interactive session), because a session-0
service cannot see the user's desktop. It is deliberately transparent: a tray icon and a startup notice
tell the user that monitoring is active. It records the active application and window title, idle state,
periodic screenshots and coarse (Wi-Fi/network) location. It never records keystrokes or password fields.
"""
import ctypes
import ctypes.wintypes as wt
import datetime as dt
import io
import os
import re
import subprocess
import threading
import time

from common import AGENT_VERSION, CREATE_NO_WINDOW, log, resource, setup_logging
from protocol import ApiError, message

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi

SAMPLE_SEC = 5          # how often we check the foreground window / idle
FLUSH_SEC = 60          # how often we upload batched events
POLICY_SEC = 300        # how often we refresh the monitoring policy
MAX_SHOT_W = 1600       # downscale screenshots to this width


def iso(ts=None):
    return dt.datetime.fromtimestamp(ts or time.time(), dt.timezone.utc).isoformat()


def idle_seconds():
    class LASTINPUTINFO(ctypes.Structure):
        _fields_ = [("cbSize", wt.UINT), ("dwTime", wt.DWORD)]
    info = LASTINPUTINFO()
    info.cbSize = ctypes.sizeof(info)
    if not user32.GetLastInputInfo(ctypes.byref(info)):
        return 0
    return max(0, (kernel32.GetTickCount() - info.dwTime) / 1000.0)


def foreground():
    """(process_exe, window_title) of the focused window, or (None, None)."""
    hwnd = user32.GetForegroundWindow()
    if not hwnd:
        return None, None
    length = user32.GetWindowTextLengthW(hwnd)
    buf = ctypes.create_unicode_buffer(length + 1)
    user32.GetWindowTextW(hwnd, buf, length + 1)
    title = buf.value or None
    pid = wt.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    proc = None
    if pid.value:
        h = kernel32.OpenProcess(0x1000, False, pid.value)  # PROCESS_QUERY_LIMITED_INFORMATION
        if h:
            try:
                size = wt.DWORD(260)
                path = ctypes.create_unicode_buffer(size.value)
                if kernel32.QueryFullProcessImageNameW(h, 0, path, ctypes.byref(size)):
                    proc = os.path.basename(path.value)
                elif psapi.GetModuleBaseNameW(h, None, path, 260):
                    proc = path.value
            finally:
                kernel32.CloseHandle(h)
    return proc, title


# ---- redact obviously sensitive window titles (password managers, auth prompts) ----
SENSITIVE = re.compile(r"password|passphrase|sign in|log ?in|credential|authenticat|secret|private key|keepass|bitwarden|1password|lastpass", re.I)


def clean_title(title):
    if not title:
        return None
    if SENSITIVE.search(title):
        return "[hidden – sensitive window]"
    return title[:300]


def grab_screenshot():
    """All-monitors JPEG via Pillow (GDI under the hood; works in the user session). Returns (bytes, w, h, monitors)."""
    from PIL import ImageGrab
    img = ImageGrab.grab(all_screens=True)
    monitors = user32.GetSystemMetrics(80) or 1  # SM_CMONITORS
    w, h = img.size
    if w > MAX_SHOT_W:
        img = img.resize((MAX_SHOT_W, int(h * MAX_SHOT_W / w)))
    if img.mode != "RGB":
        img = img.convert("RGB")
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=38, optimize=True)
    return buf.getvalue(), w, h, monitors


def wifi_location():
    try:
        out = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True,
                             timeout=8, creationflags=CREATE_NO_WINDOW).stdout
    except Exception:
        return None
    ssid = bssid = None
    for line in out.splitlines():
        m = re.match(r"\s*SSID\s*:\s*(.+)", line)
        if m and "BSSID" not in line:
            ssid = m.group(1).strip()
        m = re.match(r"\s*BSSID\s*:\s*(.+)", line)
        if m:
            bssid = m.group(1).strip()
    if ssid:
        return {"method": "wifi", "ssid": ssid, "bssid": bssid, "label": f"Wi-Fi: {ssid}"}
    return None


def private_ip():
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def os_user():
    try:
        return os.environ.get("USERDOMAIN", "") + "\\" + os.environ.get("USERNAME", "") if os.environ.get("USERNAME") else None
    except Exception:
        return None


class Collector:
    def __init__(self, cfg):
        self.cfg = cfg
        self.user = os_user()
        self.events = []          # pending foreground sessions
        self.shots = []           # pending screenshots
        self.locs = []            # pending locations
        self.cur = None           # active session being accumulated
        self.policy = cfg.get("policy") or {}
        self.last_shot = 0
        self.last_loc = 0
        self.shot_now = False
        self.lock = threading.Lock()

    # ---- foreground session accumulation ----
    def sample(self):
        idle = idle_seconds()
        active = idle < self.policy.get("idle_threshold_sec", 300)
        proc, title = foreground()
        title = clean_title(title)
        key = (proc, title)
        now = time.time()
        with self.lock:
            if self.cur and self.cur["key"] == key:
                self.cur["seconds"] += SAMPLE_SEC
                if active:
                    self.cur["active"] += SAMPLE_SEC
                self.cur["end"] = now
            else:
                self._close(now)
                self.cur = {"key": key, "process": proc, "title": title, "start": now, "end": now,
                            "seconds": SAMPLE_SEC, "active": SAMPLE_SEC if active else 0}

    def _close(self, now):
        c = self.cur
        self.cur = None
        if not c or not c["process"]:
            return
        self.events.append({
            "ts": iso(c["start"]), "end_ts": iso(c["end"] + SAMPLE_SEC), "seconds": int(c["seconds"]),
            "active_seconds": int(c["active"]), "process": c["process"], "title": c["title"], "os_user": self.user,
        })

    def capture_screenshot(self, reason="scheduled"):
        try:
            img, w, h, mon = grab_screenshot()
        except Exception as e:
            log.warning("Screenshot failed: %s", e)
            return
        import base64
        proc, title = foreground()
        with self.lock:
            self.shots.append({
                "ts": iso(), "process": proc, "title": clean_title(title), "os_user": self.user,
                "width": w, "height": h, "monitors": mon, "img": base64.b64encode(img).decode(),
            })
        log.info("Screenshot captured (%s, %d bytes)", reason, len(img))

    def capture_location(self):
        loc = wifi_location() or {"method": "network", "label": "Wired / no Wi-Fi"}
        loc.update({"ts": iso(), "private_ip": private_ip(), "os_user": self.user})
        with self.lock:
            self.locs.append(loc)

    # ---- upload ----
    def flush(self):
        with self.lock:
            self._close(time.time())
            events, shots, locs = self.events, self.shots, self.locs
            self.events, self.shots, self.locs = [], [], []
        try:
            if events:
                r = message(self.cfg, "activity", {"ts": int(time.time()), "events": events})
                if r.get("monitoring"):
                    self.policy = r["monitoring"]
            for loc in locs:
                message(self.cfg, "location", loc)
            for shot in shots:
                message(self.cfg, "screenshot", shot, timeout=120)
        except ApiError as e:
            with self.lock:  # requeue for next flush
                self.events = events + self.events
                self.locs = locs + self.locs
                self.shots = (shots + self.shots)[-20:]
            raise

    def refresh_policy(self):
        try:
            r = message(self.cfg, "policy", {"ts": int(time.time())})
            self.policy = r.get("monitoring", self.policy)
            if r.get("shot_now") and self.policy.get("screenshots"):
                self.shot_now = True
            return True
        except ApiError:
            return False
