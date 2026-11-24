"""End-to-end encrypted agent <-> portal protocol (v2).

Enrollment: X25519 ECDH between a fresh agent key and the portal's identity key (pinned from the installer
or verified by fingerprint) -> HKDF-SHA256 -> AES-256-GCM.
Messages: AES-256-GCM under a per-agent secret; AAD binds agent id, message type and timestamp.
The portal rejects stale (> 5 min) and replayed messages. Payloads are gzip-compressed before encryption.
"""
import base64
import gzip
import hashlib
import json
import os
import ssl
import time
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from common import AGENT_VERSION


class ApiError(Exception):
    def __init__(self, status, msg):
        super().__init__(f"HTTP {status}: {msg}" if status else msg)
        self.status = status
        self.msg = msg


b64 = lambda b: base64.b64encode(b).decode()
b64d = lambda s: base64.b64decode(s)


def pin_of(pub: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(pub).digest()[:16]).decode().rstrip("=")


def fingerprint_of(pub: bytes) -> str:
    h = hashlib.sha256(pub).hexdigest()[:32].upper()
    return "-".join(h[i:i + 4] for i in range(0, 32, 4))


def _hkdf(ikm, salt, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info.encode()).derive(ikm)


def _seal(key, obj, aad):
    n = os.urandom(12)
    ct = AESGCM(key).encrypt(n, gzip.compress(json.dumps(obj).encode()), aad.encode())
    return {"n": b64(n), "ct": b64(ct)}


def _open(key, env, aad):
    return json.loads(gzip.decompress(AESGCM(key).decrypt(b64d(env["n"]), b64d(env["ct"]), aad.encode())))


def http(cfg, method, path, body=None, raw=False, timeout=60):
    url = cfg["server"].rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent", f"AssetAgent/{AGENT_VERSION}")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    ctx = ssl._create_unverified_context() if url.startswith("https") and cfg.get("insecure") else None
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            payload = resp.read()
            return payload if raw else json.loads(payload or b"{}")
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("error", "")
        except Exception:
            msg = e.reason
        raise ApiError(e.code, msg) from None
    except urllib.error.URLError as e:
        reason = getattr(e, "reason", e)
        if isinstance(reason, ssl.SSLCertVerificationError):
            raise ApiError(0, "The portal's HTTPS certificate is not trusted. Use a trusted certificate or allow self-signed certificates.") from None
        raise ApiError(0, f"Cannot reach {cfg['server']} ({reason})") from None


def fetch_identity(cfg):
    """Get the portal's encryption key and verify it against the pin from the installer (if any)."""
    h = http(cfg, "GET", "/api/agent/v2/hello", timeout=20)
    pub = b64d(h["server_pub"])
    if len(pub) != 32:
        raise ApiError(0, "Portal returned an invalid identity key")
    if cfg.get("pin") and pin_of(pub) != cfg["pin"]:
        raise ApiError(0, "SECURITY: the portal's identity key does not match the one this installer was issued for. "
                          "Possible interception - installation stopped.")
    if cfg.get("server_pub") and cfg["server_pub"] != b64(pub) and not cfg.get("pin"):
        raise ApiError(0, "SECURITY: the portal's identity key changed since enrollment.")
    return pub, fingerprint_of(pub)


def enroll(cfg, inv):
    spub = b64d(cfg["server_pub"]) if cfg.get("server_pub") else fetch_identity(cfg)[0]
    eph = X25519PrivateKey.generate()
    epk = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key = _hkdf(eph.exchange(X25519PublicKey.from_public_bytes(spub)), epk + spub, "assetagent/enroll/v2")
    body = _seal(key, {
        "key": cfg["key"], "ts": int(time.time()), "agent_version": AGENT_VERSION, "system": inv["system"], "os": inv["os"],
        "macs": [n["mac"] for n in inv["nics"] if n.get("mac")],
    }, "enroll")
    body["epk"] = b64(epk)
    res = _open(key, http(cfg, "POST", "/api/agent/v2/enroll", body), "enroll-resp")
    cfg.update(agent_id=res["agent_id"], secret=res["secret"], asset_id=res.get("asset_id"),
               interval_min=res.get("interval_min", 60), server_pub=b64(spub))
    return res


def message(cfg, kind, payload, timeout=60):
    key = _hkdf(b64d(cfg["secret"]), cfg["agent_id"].encode(), "assetagent/msg/v2")
    ts = int(time.time())
    aad = f"{cfg['agent_id']}|{kind}|{ts}"
    body = {"id": cfg["agent_id"], "t": kind, "ts": ts, **_seal(key, payload, aad)}
    return _open(key, http(cfg, "POST", "/api/agent/v2/msg", body, timeout=timeout), aad + "|resp")
