import asyncio
import json
import time
import websockets

from agent.core.blocker import block_ip
from agent.collectors.cpu import collect as cpu
from agent.collectors.memory import collect as memory
from agent.collectors.disk import collect as disk
from agent.collectors.network import collect as network
from agent.checks.suricata import collect_suricata_status

METRIC_INTERVAL = 5  # detik

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


async def send_agent_status(ws):
    while True:
        payload = {
            "type": "agent_status",
            "payload": {
                "suricata": collect_suricata_status()
            },
            "timestamp": int(time.time()),
        }

        await ws.send(json.dumps(payload))
        await asyncio.sleep(30)  # tiap 30 detik


async def run_ws(config, logger):
    ws_url = config["SERVER_URL"].replace("http", "ws") + "/ws/agent"
    logger.info(f"WS URL: {ws_url}")

    while True:
        try:
            async with websockets.connect(
                ws_url,
                extra_headers={
                    "Authorization": f"Bearer {config['API_KEY']}",
                    "X-Agent-Id": config["AGENT_ID"],  # ⚠️ konsisten
                },
                ping_interval=20,
                ping_timeout=20,
            ) as ws:
                logger.info("WebSocket connected")

                # 🔥 jalan paralel
                await asyncio.gather(
                    send_metrics(ws, logger),
                    handle_messages(ws, logger),
                    send_agent_status(ws, logger),
                )

        except Exception as e:
            logger.error(f"WebSocket error: {e}")
            await asyncio.sleep(5)
