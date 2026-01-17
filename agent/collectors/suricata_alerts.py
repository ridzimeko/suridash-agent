import json
import os
import time

def tail_eve_alerts(path: str):
    f = None
    inode = None

    while True:
        try:
            if not f:
                f = open(path, "r", buffering=1)
                inode = os.stat(path).st_ino

                # 🔥 mulai dari akhir file (abaikan isi lama)
                f.seek(0, os.SEEK_END)

            line = f.readline()
            if line:
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if data.get("event_type") == "alert":
                    yield data
            else:
                time.sleep(0.05)  # kecil biar responsif

            # log rotation: inode berubah
            if os.stat(path).st_ino != inode:
                f.close()
                f = None

        except FileNotFoundError:
            time.sleep(1)
        except Exception:
            time.sleep(0.2)
