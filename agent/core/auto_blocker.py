"""
Auto-blocker: otomatis blokir IP jika severity alert <= threshold.

Suricata severity:
  1 = paling tinggi (critical)
  2 = tinggi
  3 = sedang
  4 = rendah

Default threshold = 2 → blokir severity 1 dan 2.
"""

import os
import logging

from agent.core.blocker import block_ip, is_ip_blocked

logger = logging.getLogger("suridash-agent")

# Konfigurasi via environment
AUTO_BLOCK_ENABLED = os.environ.get("SURIDASH_AUTO_BLOCK", "true").lower() == "true"
AUTO_BLOCK_SEVERITY = int(os.environ.get("SURIDASH_AUTO_BLOCK_SEVERITY", "2"))
AUTO_BLOCK_TIMEOUT = int(os.environ.get("SURIDASH_AUTO_BLOCK_TIMEOUT",
                                         os.environ.get("SURIDASH_BLOCK_TIMEOUT", "3600")))


def should_auto_block(alert: dict) -> bool:
    """
    Cek apakah alert ini memenuhi syarat untuk auto-block.
    Return True jika severity <= threshold dan IP belum diblokir.
    """
    if not AUTO_BLOCK_ENABLED:
        return False

    a = alert.get("alert") or {}
    severity = a.get("severity")

    if severity is None:
        return False

    try:
        severity = int(severity)
    except (ValueError, TypeError):
        return False

    if severity > AUTO_BLOCK_SEVERITY:
        return False

    src_ip = alert.get("src_ip")
    if not src_ip:
        return False

    # Jangan double-block
    if is_ip_blocked(src_ip):
        return False

    return True


def auto_block_from_alert(alert: dict) -> bool:
    """
    Otomatis blokir src_ip dari alert jika severity <= threshold.
    Return True jika berhasil di-block, False jika skip/gagal.
    """
    if not should_auto_block(alert):
        return False

    src_ip = alert.get("src_ip")
    a = alert.get("alert") or {}
    severity = a.get("severity")
    signature = a.get("signature", "unknown")

    try:
        ok = block_ip(src_ip, AUTO_BLOCK_TIMEOUT)
        if ok:
            logger.warning(
                f"[auto-block] Blocked {src_ip} | severity={severity} "
                f"| sig=\"{signature}\" | timeout={AUTO_BLOCK_TIMEOUT}s"
            )
        return ok
    except Exception as e:
        logger.error(f"[auto-block] Failed to block {src_ip}: {e}")
        return False
