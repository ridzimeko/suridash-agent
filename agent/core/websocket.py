import asyncio
import json
import time
import websockets
import threading

from agent.core.blocker import block_ip
from agent.collectors.cpu import collect as cpu
from agent.collectors.memory import collect as memory
from agent.collectors.disk import collect as disk
from agent.collectors.network import collect as network
from agent.collectors.suricata import collect as suricata
from agent.collectors.system import collect as system_info
from agent.collectors.suricata_alerts import tail_eve_alerts

METRIC_INTERVAL = 5  # detik
STATUS_INTERVAL = 30  # detik

alert_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)

def collect_metrics():
    return {
        "cpu": cpu(),
        "memory": memory(),
        "disk": disk(),
        "network": network(),
    }


async def send_metrics(ws, logger):
    """Task: kirim metrics periodik"""
    while True:
        payload = {
            "type": "system_metrics",
            "payload": collect_metrics(),
            "timestamp": int(time.time()),
        }
        logger.info("Sent system metrics")
        await ws.send(json.dumps(payload))
        await asyncio.sleep(METRIC_INTERVAL)


async def handle_messages(ws, logger):
    """Task: terima command dari server"""
    async for message in ws:
        data = json.loads(message)

        if data.get("type") == "block_ip":
            ip = data.get("ip")
            duration = int(data.get("duration", 3600))
            severity = data.get("severity")

            # Optional: double-check severity di agent juga
            if severity is not None and int(severity) > 2:
                await ws.send(json.dumps({
                    "type": "block_ip_status",
                    "ip": ip,
                    "ok": False,
                    "error": "severity too low",
                }))
                continue

            # Jalankan block_ip di thread supaya tidak blocking event loop
            try:
                ok = await asyncio.to_thread(block_ip, ip, duration)
                logger.warning(f"Blocked IP {ip} for {duration}s (ok={ok})")

                await ws.send(json.dumps({
                    "type": "block_ip_status",
                    "ip": ip,
                    "duration": duration,
                    "ok": bool(ok),
                }))
            except Exception as e:
                logger.error(f"Block IP failed: {e}")
                await ws.send(json.dumps({
                    "type": "block_ip_status",
                    "ip": ip,
                    "duration": duration,
                    "ok": False,
                    "error": str(e),
                }))


async def send_agent_status(ws, logger):
    while True:
        payload = {
            "type": "agent_status",
            "payload": {
                "suricata": suricata(),
                "system": system_info(),
                "rules_loaded": suricata.get_rules_loaded(),
            },
            "timestamp": int(time.time()),
        }

        logger.info("Sent agent status payload")

        await ws.send(json.dumps(payload))
        await asyncio.sleep(STATUS_INTERVAL)  


# =========================
# SURICATA ALERT PIPELINE
# =========================
def suricata_tail_worker(eve_path, logger, loop):
    logger.info(f"Suricata tail worker started ({eve_path})")

    for alert in tail_eve_alerts(eve_path):
        try:
            asyncio.run_coroutine_threadsafe(
                alert_queue.put(alert),
                loop,
            )
        except Exception as e:
            logger.error(f"Queue error: {e}")


async def send_suricata_alerts(ws, logger):
    while True:
        alert = await alert_queue.get()

        payload = {
            "type": "suricata_alert",
            "payload": {
                "signature": alert["alert"]["signature"],
                "signatureId": alert["alert"]["signature_id"],
                "timestamp": alert.get("timestamp"),
                "srcIp": alert.get("src_ip"),
                "destIp": alert.get("dest_ip"),
                "srcPort": alert.get("src_port"),
                "destPort": alert.get("dest_port"),
                "protocol": alert.get("proto"),
                "category": alert["alert"]["category"],
                "severity": alert["alert"]["severity"],
            },
        }

        logger.info(f"Sent Suricata alert: {alert['alert']['signature']}")
        await ws.send(json.dumps(payload))

async def run_ws(config, logger):
    ws_url = config["SERVER_URL"].replace("http", "ws") + "/ws/agent"
    logger.info(f"Connecting to {ws_url}")

    while True:
        try:
            async with websockets.connect(
                ws_url,
                extra_headers={
                    "Authorization": f"Bearer {config['API_KEY']}",
                    "X-Agent-Id": config["AGENT_ID"],
                },
                ping_interval=20,
                ping_timeout=20,
            ) as ws:
                logger.info("WebSocket connected")

                suricata_status = suricata()
                eve_log_path = suricata_status.get("eveLogPath")

                tasks = [
                    send_metrics(ws, logger),
                    send_agent_status(ws, logger),
                    handle_messages(ws, logger),
                ]

                loop = asyncio.get_running_loop()

                if eve_log_path:
                    logger.info(f"Streaming Suricata alerts from {eve_log_path}")

                    threading.Thread(
                        target=suricata_tail_worker,
                        args=(eve_log_path, logger, loop),
                        daemon=True,
                    ).start()

                    tasks.append(send_suricata_alerts(ws, logger))
                else:
                    logger.warning("Suricata eve log not found, alert disabled")

                await asyncio.gather(*tasks)

        except Exception as e:
            logger.error(f"WebSocket error: {e}")
            await asyncio.sleep(5)