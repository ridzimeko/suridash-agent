import time
import hashlib
from typing import Dict, Tuple

# key -> expire_ts
_CACHE: Dict[str, float] = {}
MAX_KEYS = 50_000

def _cleanup(now: float):
    if len(_CACHE) <= MAX_KEYS:
        return
    # bersihin yang expired dulu
    expired = [k for k, exp in _CACHE.items() if exp <= now]
    for k in expired[: MAX_KEYS // 2]:
        _CACHE.pop(k, None)
    # kalau masih kebanyakan, reset
    if len(_CACHE) > MAX_KEYS:
        _CACHE.clear()

def fingerprint_suricata_alert(alert: dict, bucket_seconds: int = 5) -> str:
    """
    Fingerprint stabil untuk dedup.
    Dedup per bucket waktu agar flood alert yang sama dianggap duplikat.
    """
    a = alert.get("alert") or {}

    src_ip = alert.get("src_ip") or ""
    dest_ip = alert.get("dest_ip") or ""
    proto = alert.get("proto") or ""
    src_port = str(alert.get("src_port") or 0)
    dest_port = str(alert.get("dest_port") or 0)

    sig_id = str(a.get("signature_id") or 0)
    rev = str(a.get("rev") or 0)
    severity = str(a.get("severity") or 0)

    # time bucket (gunakan waktu agent agar sederhana)
    bucket = int(time.time() // bucket_seconds)

    raw = "|".join([src_ip, dest_ip, proto, src_port, dest_port, sig_id, rev, severity, str(bucket)])
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()

def dedup_allow(key: str, ttl_seconds: int = 10) -> bool:
    """
    Return True kalau boleh kirim (belum pernah dalam TTL).
    """
    now = time.time()
    _cleanup(now)

    exp = _CACHE.get(key)
    if exp and exp > now:
        return False

    _CACHE[key] = now + ttl_seconds
    return True