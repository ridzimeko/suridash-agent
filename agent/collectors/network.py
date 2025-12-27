# agent/collectors/network.py
import psutil
import time

_prev = None
_prev_time = None

def collect():
    global _prev, _prev_time

    now = time.time()
    net = psutil.net_io_counters()

    if _prev is None:
        _prev = net
        _prev_time = now
        return {
            "rx": 0,
            "tx": 0,
        }

    interval = now - _prev_time

    rx_rate = (net.bytes_recv - _prev.bytes_recv) / interval
    tx_rate = (net.bytes_sent - _prev.bytes_sent) / interval

    _prev = net
    _prev_time = now

    return {
        "recv": int(rx_rate),  # bytes/sec
        "sent": int(tx_rate),
    }
