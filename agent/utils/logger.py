import logging
import os

def setup_logger():
    log_dir = "/var/log/suridash-agent"
    
    agent_handlers = [logging.StreamHandler()]
    blocker_handlers = []
    
    try:
        os.makedirs(log_dir, exist_ok=True)
        agent_log_file = os.path.join(log_dir, "agent.log")
        blocker_log_file = os.path.join(log_dir, "blocked_ips.log")
        
        agent_handlers.append(logging.FileHandler(agent_log_file))
        blocker_handlers.append(logging.FileHandler(blocker_log_file))
    except PermissionError:
        pass
        
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=agent_handlers
    )
    
    block_logger = logging.getLogger("suridash-blocker")
    block_logger.setLevel(logging.INFO)
    block_logger.propagate = True
    
    # clear existing handlers if any to avoid duplication on re-init
    if block_logger.hasHandlers():
        block_logger.handlers.clear()
        
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    for h in blocker_handlers:
        h.setFormatter(formatter)
        block_logger.addHandler(h)

    return logging.getLogger("suridash-agent")
