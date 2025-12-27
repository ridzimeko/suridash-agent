import psutil

def collect():
    return {
        "percent": psutil.cpu_percent(interval=1),
        "cores": psutil.cpu_count(),
    }
