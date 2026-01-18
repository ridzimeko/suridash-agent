import os
import subprocess
import ipaddress
import time
from typing import Dict, Tuple

IPSET_NAME = os.environ.get("SURIDASH_IPSET_NAME", "suridash-blacklist")
DEFAULT_TIMEOUT = int(os.environ.get("SURIDASH_BLOCK_TIMEOUT", "3600"))

_block_cooldown = {}  # ip -> last_block_ts
COOLDOWN_SECONDS = 5

_BLOCKED_CACHE: Dict[str, Tuple[bool, float]] = {}
CACHE_TTL_SECONDS = int(os.environ.get("SURIDASH_IPSET_CACHE_TTL", "3"))  # kecil tapi efektif
MAX_CACHE_SIZE = 10_000

def _run(cmd: list[str]):
    subprocess.run(cmd, check=True)

def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        )
    except ValueError:
        return False

def block_ip(ip: str, timeout: int | None = None) -> bool:
    if not _is_public_ip(ip):
        print("[blocker] skip non-public ip:", ip)
        return False

    now = time.time()
    last = _block_cooldown.get(ip, 0)
    if now - last < COOLDOWN_SECONDS:
        return True  # silently ignore spam

    _block_cooldown[ip] = now
    timeout = timeout or DEFAULT_TIMEOUT

    _run(["sudo", "ipset", "add", IPSET_NAME, ip, "-exist"])
    print(f"[blocker] blocked {ip} for {timeout}s")
    return True

def unblock_ip(ip: str) -> bool:
    if not _is_public_ip(ip):
        return False

    try:
        _run(["sudo", "ipset", "del", IPSET_NAME, ip])
        print("[blocker] unblocked", ip)
        return True
    except subprocess.CalledProcessError:
        return False

def is_ip_blocked(ip: str) -> bool:
    """
    Cek apakah ip ada di ipset.
    Cepat karena pakai cache TTL.
    """
    if not ip or not _is_public_ip(ip):
        return False

    now = time.time()
    cached = _BLOCKED_CACHE.get(ip)
    if cached and cached[1] > now:
        return cached[0]

    # menjaga cache tidak membesar terus
    if len(_BLOCKED_CACHE) > MAX_CACHE_SIZE:
        _BLOCKED_CACHE.clear()

    # ipset test <set> <ip> -> exit code 0 kalau ada, 1 kalau tidak ada
    try:
        subprocess.run(
            ["ipset", "test", IPSET_NAME, ip],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _BLOCKED_CACHE[ip] = (True, now + CACHE_TTL_SECONDS)
        return True
    except subprocess.CalledProcessError:
        _BLOCKED_CACHE[ip] = (False, now + CACHE_TTL_SECONDS)
        return False