import os
from dotenv import load_dotenv

def load_config():
    if os.getenv("ENV") == "development":
        load_dotenv(".env")
    else:
        load_dotenv("/etc/suridash-agent/config.env")

    return {
        "AGENT_ID": os.getenv("AGENT_ID"),
        "API_KEY": os.getenv("API_KEY"),
        "SERVER_URL": os.getenv("SERVER_URL"),
    }
