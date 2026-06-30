import asyncio
import json
import time
import websockets
import threading

from agent.core.blocker import block_ip, is_ip_blocked, unblock_ip
from agent.core.auto_blocker import auto_block_from_alert, AUTO_BLOCK_TIMEOUT
from agent.collectors.cpu import collect as cpu
from agent.collectors.memory import collect as memory
from agent.collectors.disk import collect as disk
from agent.collectors.network import collect as network
from agent.collectors.suricata import collect as suricata
from agent.collectors.system import collect as system_info
from agent.collectors.suricata_alerts import tail_eve_alerts
from agent.utils.deduper import dedup_allow, fingerprint_suricata_alert

METRIC_INTERVAL = 5  # detik
STATUS_INTERVAL = 10  # detik

alert_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
_tail_thread_started = False

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
            reason = data.get("reason")

            # Optional: double-check severity di agent juga
            if severity is not None and int(severity) > 2:
                await ws.send(json.dumps({
                    "type": "block_ip_ack",
                    "ip": ip,
                    "ok": False,
                    "error": "severity too low",
                    "reason": reason,
                }))
                continue

            # Jalankan block_ip di thread supaya tidak blocking event loop
            try:
                ok = await asyncio.to_thread(block_ip, ip, duration)
                logger.warning(f"Blocked IP {ip} for {duration}s (ok={ok}, reason={reason})")

                await ws.send(json.dumps({
                    "type": "block_ip_ack",
                    "ip": ip,
                    "duration": duration,
                    "ok": bool(ok),
                    "reason": reason,
                }))
            except Exception as e:
                logger.error(f"Block IP failed: {e}")
                await ws.send(json.dumps({
                    "type": "block_ip_ack",
                    "ip": ip,
                    "duration": duration,
                    "ok": False,
                    "error": str(e),
                    "reason": reason,
                }))

        elif data.get("type") == "unblock_ip":
            ip = data.get("ip")

            try:
                ok = await asyncio.to_thread(unblock_ip, ip)
                logger.warning(f"Unblocked IP {ip} (ok={ok})")
                await ws.send(json.dumps({
                    "type": "unblock_ip_ack",
                    "ip": ip,
                    "ok": bool(ok),
                }))
            except Exception as e:
                await ws.send(json.dumps({
                    "type": "unblock_ip_ack",
                    "ip": ip,
                    "ok": False,
                    "error": str(e),
                }))


async def send_agent_status(ws, logger):
    while True:
        logger.info("Fetching agent status...")
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
        await asyncio.sleep(STATUS_INTERVAL)  


# =========================
# SURICATA ALERT PIPELINE
# =========================
def suricata_tail_worker(config, eve_path, logger, loop):
    logger.info(f"Suricata tail worker started ({eve_path})")

    for alert in tail_eve_alerts(eve_path):
        try:
            src_ip = alert.get("src_ip")

            # ✅ DEDUP: kalau fingerprint sudah pernah dikirim -> skip
            bucket_sec = config.get("DEDUP_BUCKET", 20)
            ttl_sec = config.get("DEDUP_TTL", 25)
            key = fingerprint_suricata_alert(alert, bucket_seconds=bucket_sec)
            if not dedup_allow(key, ttl_seconds=ttl_sec):
                sig_name = (alert.get("alert") or {}).get("signature", "unknown")
                logger.info(f"Alert deduplicated/delayed: {sig_name}")
                continue

            def _enqueue(a=alert):
                try:
                    alert_queue.put_nowait(a)
                except asyncio.QueueFull:
                    logger.warning("Alert queue full, dropping alert")

            loop.call_soon_threadsafe(_enqueue)

        except Exception as e:
            logger.error(f"Queue error: {e}")

def _build_alert_payload(alert: dict, is_blocked: bool = False) -> dict:
    # lebih aman: pakai get() agar tidak KeyError
    a = alert.get("alert") or {}
    return {
        "signature": a.get("signature"),
        "signatureId": a.get("signature_id"),
        "timestamp": alert.get("timestamp"),
        "srcIp": alert.get("src_ip"),
        "destIp": alert.get("dest_ip"),
        "srcPort": alert.get("src_port"),
        "destPort": alert.get("dest_port"),
        "protocol": alert.get("proto"),
        "category": a.get("category"),
        "severity": a.get("severity"),
        "status": "blocked" if is_blocked else "allowed",
        "duration": AUTO_BLOCK_TIMEOUT if is_blocked else 0,
    }

async def send_suricata_alerts(ws, logger):
    while True:
        alert = await alert_queue.get()

        try:
            src_ip = alert.get("src_ip")

            # Cek apakah IP sudah dalam keadaan terblokir sebelumnya
            already_blocked = is_ip_blocked(src_ip) if src_ip else False

            # 🛡️ AUTO-BLOCK: blokir IP jika severity <= threshold
            just_blocked = await asyncio.to_thread(auto_block_from_alert, alert)
            if just_blocked:
                a = alert.get("alert") or {}
                try:
                    await ws.send(json.dumps({
                        "type": "block_ip_ack",
                        "ip": src_ip,
                        "duration": AUTO_BLOCK_TIMEOUT,
                        "ok": True,
                        "severity": a.get("severity"),
                        "signature": a.get("signature"),
                        "reason": a.get("signature"),
                    }))
                    logger.info(f"Sent block_ip_ack for auto-blocked {src_ip} (reason={a.get('signature')})")
                except Exception as e:
                    logger.error(f"Failed to send block_ip_ack: {e}")

            is_now_blocked = already_blocked or just_blocked

            payload = {
                "type": "suricata_alert",
                "payload": _build_alert_payload(alert, is_blocked=is_now_blocked),
            }

            sig = (alert.get("alert") or {}).get("signature", "unknown")
            logger.info(f"Sent Suricata alert: {sig}")
            await ws.send(json.dumps(payload))

        finally:
            alert_queue.task_done()

async def run_ws(config, logger):
    global _tail_thread_started
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

                loop = asyncio.get_running_loop()

                if eve_log_path:
                    logger.info(f"Suricata alerts enabled, log path: {eve_log_path}")
                    if not _tail_thread_started:
                        threading.Thread(
                            target=suricata_tail_worker,
                            args=(config, eve_log_path, logger, loop),
                            daemon=True,
                        ).start()
                        _tail_thread_started = True
                else:
                    logger.warning("Suricata eve log not found, alert disabled")

                # Buat task dengan wrapper
                tasks = [
                    asyncio.create_task(send_metrics(ws, logger)),
                    asyncio.create_task(send_agent_status(ws, logger)),
                    asyncio.create_task(handle_messages(ws, logger)),
                ]
                
                if eve_log_path:
                    tasks.append(asyncio.create_task(send_suricata_alerts(ws, logger)))

                # Tunggu sampai salah satu task selesai/error (termasuk websocket putus)
                done, pending = await asyncio.wait(
                    tasks,
                    return_when=asyncio.FIRST_COMPLETED
                )

                # Cancel semua task yang masih jalan
                for task in pending:
                    task.cancel()
                    
                # Raise exception jika ada task yang error
                for task in done:
                    task.result()

        except Exception as e:
            error_msg = str(e)
            if "<html" in error_msg.lower() or "<!doctype" in error_msg.lower():
                error_msg = "error (html response hidden)"
            logger.error(f"WebSocket error: {error_msg}")
            await asyncio.sleep(5)