import psutil

def collect():
    disk = psutil.disk_usage("/")
    return {
        "total": disk.total,
        "used": disk.used,
        "percent": disk.percent,
    }
