import os
from dotenv import load_dotenv

def load_config():
    ENV_PATH = os.environ.get("SURIDASH_ENV", "agent.env")
    load_dotenv(ENV_PATH)

    return {
        "AGENT_ID": os.getenv("AGENT_ID"),
        "API_KEY": os.getenv("API_KEY"),
        "SERVER_URL": os.getenv("SERVER_URL"),
    }
