import asyncio
import json
import time
import websockets

from agent.core.blocker import block_ip
from agent.collectors.cpu import collect as cpu
from agent.collectors.memory import collect as memory
from agent.collectors.disk import collect as disk
from agent.collectors.network import collect as network
from agent.collectors.suricata import collect as suricata
from agent.collectors.system import collect as system_info


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
            ip = data["ip"]
            duration = data.get("duration", 3600)

            block_ip(ip, duration)
            logger.warning(f"Blocked IP {ip} for {duration}s")

import time

async def send_agent_status(ws, logger):
    while True:
        payload = {
            "type": "agent_status",
            "payload": {
                "suricata": suricata(),
                "system": system_info(),
            },
            "timestamp": int(time.time()),
        }

        logger.info("Sent agent status payload")

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
