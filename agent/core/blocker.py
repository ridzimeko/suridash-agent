import subprocess

def block_ip(ip: str, timeout=3600):
    subprocess.run(
        f"ipset add suridash_blocklist {ip} timeout {timeout} -exist",
        shell=True,
        check=True,
    )
