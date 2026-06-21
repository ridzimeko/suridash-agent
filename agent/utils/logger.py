import logging
import os

def setup_logger():
    log_dir = "/var/log/suridash-agent"
    try:
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, "agent.log")
        handlers = [
            logging.StreamHandler(),
            logging.FileHandler(log_file)
        ]
    except PermissionError:
        # Fallback if no permission to create log dir/file
        handlers = [logging.StreamHandler()]
        
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers
    )
    return logging.getLogger("suridash-agent")
