import json
import os
import subprocess

SURICATA_EVE_PATHS = [
    "/var/log/suricata/eve.json",
    "/var/log/suricata/eve.log",
]

def _cmd_exists(cmd: str) -> bool:
    return subprocess.call(
        ["which", cmd],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ) == 0


def is_installed() -> bool:
    return _cmd_exists("suricata")


def is_running() -> bool:
    return subprocess.call(
        ["systemctl", "is-active", "--quiet", "suricata"]
    ) == 0


def find_eve_log():
    for path in SURICATA_EVE_PATHS:
        if os.path.isfile(path) and os.access(path, os.R_OK):
            return path
    return None

def _get_version():
    try:
        result = subprocess.run(
            ["suricata", "-V"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        output = result.stdout.strip()

        # "This is Suricata version 6.0.14 RELEASE"
        if "version" in output.lower():
            return output.replace("This is Suricata version ", "")
        return output
    except Exception:
        return None

def get_rules_loaded(eve_path):
    if not eve_path:
        return 0
    try:
        from collections import deque
        with open(eve_path, "r") as f:
            # Menggunakan deque untuk efisiensi memori (tidak membaca seluruh file ke RAM)
            lines = deque(f, maxlen=500)
            for line in reversed(list(lines)):
                try:
                    data = json.loads(line)
                    if data.get("event_type") == "stats":
                        engines = data.get("stats", {}).get("detect", {}).get("engines", [])
                        if isinstance(engines, list) and len(engines) > 0:
                            return engines[0].get("rules_loaded", 0)
                        elif isinstance(engines, dict):
                            return engines.get("rules_loaded", 0)
                except json.JSONDecodeError:
                    continue
    except Exception:
        pass
    return 0

def collect():
    installed = is_installed()
    running = is_running() if installed else False
    eve_path = find_eve_log()
    version = _get_version() if installed else None
    rules_loaded = get_rules_loaded(eve_path) if installed else 0

    last_modified = None
    if eve_path:
        last_modified = int(os.path.getmtime(eve_path))

    return {
        "installed": installed,
        "running": running,
        "eveLogExists": eve_path is not None,
        "eveLogPath": eve_path,
        "version": version,
        "rulesLoaded": rules_loaded,
        "lastModified": last_modified,
    }
