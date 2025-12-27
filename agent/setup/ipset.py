import subprocess

def run(cmd: str):
    subprocess.run(cmd, shell=True, check=True)

def ensure_ipset():
    run("ipset create suridash_blocklist hash:ip timeout 3600 -exist")
