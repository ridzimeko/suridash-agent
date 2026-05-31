import subprocess
import sys
from agent.config.loader import load_config
from agent.utils.logger import setup_logger

def main(version: str):
    config = load_config()
    logger = setup_logger()

    base_url = config.get("SERVER_URL", "https://suridash.slayerwitch.my.id")
    script_url = f"{base_url}/api/agent/update-script"

    logger.info(f"Starting agent update to version: {version}")
    logger.info(f"Fetching update script from: {script_url}")

    cmd = f"curl -sL {script_url} | bash -s -- {version}"
    try:
        # Menjalankan perintah update secara sinkron sehingga output bisa dilihat user
        subprocess.run(cmd, shell=True, check=True)
        logger.info("Update command finished successfully.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Update script failed with exit code: {e.returncode}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error during update: {e}")
        sys.exit(1)
