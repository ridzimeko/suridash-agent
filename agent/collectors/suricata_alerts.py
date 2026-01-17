import os
import json
import time

OFFSET_FILE = os.path.expanduser("~/.suridash_alerts.offset") 

def load_offset():
    try:
        with open(OFFSET_FILE, "r") as f:
            return int(f.read().strip())
    except Exception:
        return 0


def save_offset(offset: int):
    os.makedirs(os.path.dirname(OFFSET_FILE), exist_ok=True)
    with open(OFFSET_FILE, "w") as f:
        f.write(str(offset))


def tail_eve_alerts(path):
    offset = load_offset()
    inode = None
    f = None

    while True:
        try:
            if not f:
                f = open(path, "r")
                inode = os.stat(path).st_ino

                # 🔥 resume offset
                f.seek(offset)

            line = f.readline()
            if line:
                offset = f.tell()
                save_offset(offset)

                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if data.get("event_type") == "alert":
                    yield data
            else:
                time.sleep(0.5)

            # 🔁 log rotation detected
            if os.stat(path).st_ino != inode:
                f.close()
                f = None
                offset = 0
                save_offset(0)

        except FileNotFoundError:
            time.sleep(1)