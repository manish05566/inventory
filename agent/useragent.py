"""User-session monitoring host: a visible tray icon + the collection loop.

Launched by the service in the interactive session (see usersession.py). Transparent by design:
a tray icon and a startup balloon make it obvious to the signed-in user that monitoring is active,
and a menu explains exactly what is recorded.
"""
import ctypes
import os
import threading
import time

from common import AGENT_VERSION, PRODUCT, log, resource, setup_logging
from monitor import Collector, FLUSH_SEC, POLICY_SEC, SAMPLE_SEC


def _cfg_from_env():
    srv = os.environ.get("ASSETAGENT_SRV")
    aid = os.environ.get("ASSETAGENT_AID")
    sec = os.environ.get("ASSETAGENT_SEC")
    if not (srv and aid and sec):
        return None
    return {"server": srv, "agent_id": aid, "secret": sec,
            "insecure": os.environ.get("ASSETAGENT_INSECURE") == "1",
            "pin": os.environ.get("ASSETAGENT_PIN") or None}


class Tray:
    """Minimal Shell_NotifyIcon tray icon with a right-click menu, so monitoring is never hidden."""
    def __init__(self, notice, on_quit=None):
        import win32con
        import win32gui
        self.win32con, self.win32gui = win32con, win32gui
        self.notice = notice or "This computer is managed by IT. Activity may be recorded."
        self.on_quit = on_quit
        self.hwnd = None
        self._id_about = 1023
        wc = win32gui.WNDCLASS()
        wc.lpszClassName = "AssetAgentTray"
        wc.lpfnWndProc = self._proc
        wc.hInstance = win32gui.GetModuleHandle(None)
        self._atom = win32gui.RegisterClass(wc)
        self.hwnd = win32gui.CreateWindow(self._atom, PRODUCT, 0, 0, 0, 0, 0, 0, 0, wc.hInstance, None)
        win32gui.UpdateWindow(self.hwnd)
        self._add_icon()

    def _load_icon(self):
        import win32con
        import win32gui
        try:
            return win32gui.LoadImage(0, str(resource("icon.ico")), win32con.IMAGE_ICON, 0, 0,
                                      win32con.LR_LOADFROMFILE | win32con.LR_DEFAULTSIZE)
        except Exception:
            return win32gui.LoadIcon(0, win32con.IDI_APPLICATION)

    def _add_icon(self):
        wg, wc = self.win32gui, self.win32con
        flags = wg.NIF_ICON | wg.NIF_MESSAGE | wg.NIF_TIP
        wg.Shell_NotifyIcon(wg.NIM_ADD, (self.hwnd, 0, flags, wc.WM_USER + 20, self._load_icon(),
                                         f"{PRODUCT} — activity monitoring active"))

    def balloon(self, title, text):
        wg = self.win32gui
        try:
            wg.Shell_NotifyIcon(wg.NIM_MODIFY, (self.hwnd, 0, wg.NIF_INFO, self.win32con.WM_USER + 20,
                                                self._load_icon(), f"{PRODUCT} — monitoring active", text, 10, title, wg.NIIF_INFO))
        except Exception as e:
            log.warning("balloon failed: %s", e)

    def _proc(self, hwnd, msg, wparam, lparam):
        wg, wc = self.win32gui, self.win32con
        if msg == wc.WM_USER + 20 and lparam in (wc.WM_RBUTTONUP, wc.WM_LBUTTONUP):
            menu = wg.CreatePopupMenu()
            wg.AppendMenu(menu, wc.MF_STRING, self._id_about, "What is monitored?")
            pos = wg.GetCursorPos()
            wg.SetForegroundWindow(hwnd)
            wg.TrackPopupMenu(menu, wc.TPM_LEFTALIGN, pos[0], pos[1], 0, hwnd, None)
        elif msg == wc.WM_COMMAND and wg.LOWORD(wparam) == self._id_about:
            ctypes.windll.user32.MessageBoxW(0, self.notice + "\n\nKeystrokes and passwords are never recorded.",
                                             f"{PRODUCT} — privacy notice", 0x40)
        elif msg == wc.WM_DESTROY:
            wg.Shell_NotifyIcon(wg.NIM_DELETE, (self.hwnd, 0))
            wg.PostQuitMessage(0)
            if self.on_quit:
                self.on_quit()
        return 0

    def destroy(self):
        try:
            self.win32gui.DestroyWindow(self.hwnd)
        except Exception:
            pass

    def pump(self):
        self.win32gui.PumpMessages()


def _loop(col, tray, stop):
    last_flush = last_policy = time.time()
    # Show the transparency notice once per logon session.
    try:
        marker = os.path.join(os.environ.get("LOCALAPPDATA", os.environ.get("TEMP", ".")), "AssetAgent", "notice.flag")
        os.makedirs(os.path.dirname(marker), exist_ok=True)
        day = time.strftime("%Y%m%d")
        if tray and (not os.path.exists(marker) or open(marker).read() != day):
            tray.balloon("Activity monitoring active", col.policy.get("notice") or
                         "Application usage and periodic screenshots are recorded while you are signed in.")
            open(marker, "w").write(day)
    except Exception:
        pass
    while not stop.is_set():
        try:
            if col.policy.get("activity", True):
                col.sample()
            now = time.time()
            if col.shot_now or (col.policy.get("screenshots") and now - col.last_shot >= col.policy.get("screenshot_interval_min", 15) * 60):
                col.capture_screenshot("on-demand" if col.shot_now else "scheduled")
                col.last_shot = now
                col.shot_now = False
            if col.policy.get("location") and now - col.last_loc >= 600:
                col.capture_location()
                col.last_loc = now
            if now - last_flush >= FLUSH_SEC:
                try:
                    col.flush()
                except Exception as e:
                    log.warning("Upload failed: %s", e)
                last_flush = now
            if now - last_policy >= POLICY_SEC:
                col.refresh_policy()
                last_policy = now
                if not col.policy.get("enabled"):
                    log.info("Monitoring disabled by policy — stopping user agent")
                    break
        except Exception as e:
            log.warning("Monitor cycle error: %s", e)
        stop.wait(SAMPLE_SEC)
    try:
        col.flush()
    except Exception:
        pass
    if tray:
        tray.destroy()


def run():
    setup_logging("useragent")
    cfg = _cfg_from_env()
    if not cfg:
        log.error("User agent started without credentials — exiting")
        return 2
    # Single instance per session.
    mutex = ctypes.windll.kernel32.CreateMutexW(None, False, "Local\\AssetAgentUserMon")
    if ctypes.windll.kernel32.GetLastError() == 183:
        return 0
    col = Collector(cfg)
    col.refresh_policy()
    if not col.policy.get("enabled"):
        log.info("Monitoring not enabled — exiting")
        return 0
    log.info("User monitoring started (%s) for %s", AGENT_VERSION, col.user)
    stop = threading.Event()
    tray = None
    try:
        tray = Tray(col.policy.get("notice"), on_quit=stop.set)
    except Exception as e:
        log.warning("Tray icon unavailable (%s) — continuing without it", e)
    worker = threading.Thread(target=_loop, args=(col, tray, stop), daemon=True)
    worker.start()
    if tray:
        tray.pump()          # blocks on the Windows message loop until the icon is destroyed
        stop.set()
    else:
        while worker.is_alive():
            time.sleep(1)
    worker.join(timeout=10)
    return 0
