import threading
import asyncio

from agent.config.loader import load_config
from agent.utils.logger import setup_logger
from agent.core.heartbeat import start_heartbeat
from agent.core.websocket import run_ws

class Agent:
    def __init__(self):
        self.config = load_config()
        self.logger = setup_logger()

        if not all(self.config.values()):
            raise RuntimeError("Missing agent configuration")

    def run(self):
        self.logger.info("Starting SuriDash Agent")

        # Heartbeat thread
        t = threading.Thread(
            target=start_heartbeat,
            args=(self.config, self.logger),
            daemon=True,
        )
        t.start()

        # WebSocket loop
        asyncio.run(run_ws(self.config, self.logger))
