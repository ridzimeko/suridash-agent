import time
import requests

def start_heartbeat(config, logger):
    url = f"{config['SERVER_URL']}/api/agents/heartbeat"
    headers = {
        "Authorization": f"Bearer {config['API_KEY']}"
    }

    while True:
        try:
            response = requests.post(
                url,
                json={"agent_id": config["AGENT_ID"]},
                headers=headers,
                timeout=5,
            )

            # === LOG BERDASARKAN RESPONSE ===
            if response.ok:  # status 2xx
                logger.info(
                    f"Heartbeat success | status={response.status_code} | response={response.text}"
                )
            else:
                logger.warning(
                    f"Heartbeat failed | status={response.status_code} | response={response.text}"
                )

        except requests.exceptions.RequestException as e:
            logger.error(f"Heartbeat request error: {e}")

        time.sleep(30)
