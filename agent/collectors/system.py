import socket
import platform

def _get_linux_distro():
    try:
        with open("/etc/os-release") as f:
            data = {}
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    data[k] = v.strip('"')

        return {
            "name": data.get("NAME"),
            "version": data.get("VERSION"),
            "id": data.get("ID"),
        }
    except Exception:
        return None

def collect():
    distro = _get_linux_distro()

    return {
        "hostname": socket.gethostname(),
        "os": {
            "name": platform.system(),
            "version": platform.release(),
            "distro": distro,
        },
        "architecture": platform.machine(),
    }
