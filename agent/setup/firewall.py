import subprocess

def run(cmd: str):
    subprocess.run(cmd, shell=True, check=True)

def setup_firewall():
    # ipset
    run("ipset create suridash_blocklist hash:ip timeout 3600 -exist")

    # iptables rule (cek dulu)
    run(
        "iptables -C INPUT -m set --match-set suridash_blocklist src -j DROP "
        "|| iptables -I INPUT -m set --match-set suridash_blocklist src -j DROP"
    )
