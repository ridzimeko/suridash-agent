import os
import subprocess
import time

SURICATA_EVE_PATHS = [
    "/var/log/suricata/eve.json",
    "/var/log/suricata/eve.log",
]

def is_suricata_installed() -> bool:
    return subprocess.call(
        ["which", "suricata"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ) == 0


def is_suricata_running() -> bool:
    return subprocess.call(
        ["systemctl", "is-active", "--quiet", "suricata"]
    ) == 0


def find_eve_log():
    for path in SURICATA_EVE_PATHS:
        if os.path.isfile(path) and os.access(path, os.R_OK):
            return path
    return None


def collect_suricata_status():
    installed = is_suricata_installed()
    running = is_suricata_running() if installed else False
    eve_path = find_eve_log()

    last_modified = None
    if eve_path:
        last_modified = int(os.path.getmtime(eve_path))

    return {
        "installed": installed,
        "running": running,
        "eveLogExists": eve_path is not None,
        "eveLogPath": eve_path,
        "lastModified": last_modified,
    }
