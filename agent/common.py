"""Shared constants, logging, helpers and the DPAPI-encrypted configuration store."""
import ctypes
import json
import logging
import logging.handlers
import os
import subprocess
import sys
from pathlib import Path

AGENT_VERSION = "2.1.0"
PRODUCT = "Asset Inventory Agent"
PUBLISHER = "IT Asset Management"
SERVICE_NAME = "AssetAgent"
EXE_NAME = "AssetAgent.exe"
SETUP_NAME = "AssetAgentSetup.exe"
UNINSTALL_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AssetAgent"
INSTALL_DIR = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "AssetAgent"
DATA_DIR = Path(os.environ.get("ASSETAGENT_DATA_DIR") or Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "AssetAgent")
LOG_DIR = DATA_DIR / "logs"
CONFIG_FILE = DATA_DIR / "config.dat"
LEGACY_CONFIG = DATA_DIR / "config.json"
HEARTBEAT_SEC = 60
CREATE_NO_WINDOW = 0x08000000
DETACHED = 0x00000008 | 0x00000200 | 0x01000000  # DETACHED_PROCESS | NEW_PROCESS_GROUP | BREAKAWAY_FROM_JOB
DPAPI_ENTROPY = b"AssetAgent/config/v2"

log = logging.getLogger("agent")


def resource(name):
    """Path of a file bundled with the executable (PyInstaller) or next to the source."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).parent))
    return base / "assets" / name


def setup_logging(name="agent", console=False):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log.setLevel(logging.INFO)
    if any(isinstance(h, logging.handlers.RotatingFileHandler) for h in log.handlers):
        return
    fh = logging.handlers.RotatingFileHandler(LOG_DIR / f"{name}.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(fh)
    if console and sys.stdout:
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(logging.Formatter("%(message)s"))
        log.addHandler(ch)


def attach_console():
    """The agent is a windowed exe; when started from cmd/PowerShell, print to that console."""
    try:
        import msvcrt
        k32 = ctypes.windll.kernel32
        k32.GetStdHandle.restype = ctypes.c_void_p
        h = k32.GetStdHandle(-11)  # redirected to a pipe/file (scripts, deployment tools)
        if h and h != ctypes.c_void_p(-1).value:
            sys.stdout = open(msvcrt.open_osfhandle(h, os.O_WRONLY), "w", encoding="utf-8", buffering=1, closefd=False)
            sys.stderr = sys.stdout
            return
        if k32.AttachConsole(-1):
            sys.stdout = open("CONOUT$", "w", encoding="utf-8", buffering=1)
            sys.stderr = sys.stdout
            print()
    except Exception:
        pass


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_elevated(args):
    """Relaunch this executable elevated (UAC prompt). Returns True if the user approved."""
    params = subprocess.list2cmdline(args)
    return ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1) > 32


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def gb(n):
    try:
        return round(float(n) / 1024 ** 3, 1)
    except (TypeError, ValueError):
        return None


def clean(s):
    if s is None:
        return None
    s = str(s).strip().strip("\x00")
    return s or None


def secure_dir(path):
    """Restrict a folder to SYSTEM and Administrators only."""
    subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"],
                   capture_output=True, creationflags=CREATE_NO_WINDOW)


# ------------------------------------------------------------------ encrypted config (DPAPI, machine scope)
def _protect(data: bytes) -> bytes:
    import win32crypt
    return win32crypt.CryptProtectData(data, "AssetAgent", DPAPI_ENTROPY, None, None, 0x4 | 0x1)  # LOCAL_MACHINE|UI_FORBIDDEN


def _unprotect(data: bytes) -> bytes:
    import win32crypt
    return win32crypt.CryptUnprotectData(data, DPAPI_ENTROPY, None, None, 0x1)[1]


def load_config():
    try:
        return json.loads(_unprotect(CONFIG_FILE.read_bytes()))
    except FileNotFoundError:
        pass
    except Exception as e:
        log.warning("Could not read configuration: %s", e)
        return {}
    try:  # migrate the v1 plaintext config
        cfg = json.loads(LEGACY_CONFIG.read_text(encoding="utf-8"))
        return {"server": cfg.get("server"), "key": cfg.get("key"), "insecure": cfg.get("insecure", False)}
    except Exception:
        return {}


def save_config(cfg):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_FILE.with_suffix(".tmp")
    tmp.write_bytes(_protect(json.dumps(cfg).encode()))
    os.replace(tmp, CONFIG_FILE)
    if LEGACY_CONFIG.exists():
        LEGACY_CONFIG.unlink()
