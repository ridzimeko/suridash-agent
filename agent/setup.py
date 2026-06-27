#!/usr/bin/env python3
import os
import shutil
import subprocess
import sys
from typing import List

SET_NAME = os.environ.get("SURIDASH_IPSET_NAME", "suridash-blacklist")
AUTO_BLOCK_TIMEOUT = int(os.environ.get("SURIDASH_AUTO_BLOCK_TIMEOUT", "3600"))

def run(cmd: List[str], check=True):
    print("+", " ".join(cmd))
    return subprocess.run(cmd, check=check)

def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def require_root():
    if os.geteuid() != 0:
        print("❌ Please run as root: sudo python -m agent.setup")
        sys.exit(1)

def install_packages():
    print("=== [1/6] Installing ipset + iptables ===")

    if have("apt"):
        print("Detected Debian/Ubuntu")
        run(["apt", "update", "-y"])
        run(["apt", "install", "-y", "ipset", "iptables", "ipset-persistent", "netfilter-persistent"])

    elif have("dnf"):
        print("Detected RHEL/CentOS/Rocky/Alma")
        run(["dnf", "install", "-y", "ipset", "iptables-services", "iptables"])

    elif have("apk"):
        print("Detected Alpine Linux")
        run(["apk", "add", "ipset", "iptables"])

    else:
        print("❌ Unsupported Linux distribution.")
        sys.exit(1)

    print("✔ ipset + iptables installed")

def create_ipset():
    print(f"=== [2/6] Creating ipset {SET_NAME} ===")
    run(["ipset", "create", SET_NAME, "hash:ip", "family", "inet", "hashsize", "4096", "maxelem", "65536", "timeout", str(AUTO_BLOCK_TIMEOUT), "-exist"])
    print(f"✔ ipset '{SET_NAME}' created or already exists")

def ensure_iptables_rule():
    print("=== [3/6] Adding iptables DROP rule ===")

    # check rule exists
    check_cmd = ["iptables", "-C", "INPUT", "-m", "set", "--match-set", SET_NAME, "src", "-j", "DROP"]
    insert_cmd = ["iptables", "-I", "INPUT", "-m", "set", "--match-set", SET_NAME, "src", "-j", "DROP"]

    try:
        run(check_cmd, check=True)
        print("✔ DROP rule already exists")
    except subprocess.CalledProcessError:
        print("Adding rule...")
        run(insert_cmd, check=True)
        print("✔ DROP rule inserted")

def persist_rules():
    print("=== [4/6] Persist rules (if supported) ===")

    if have("netfilter-persistent"):
        print("Saving via netfilter-persistent")
        run(["netfilter-persistent", "save"], check=False)

    elif have("service"):
        # some distros support "service iptables save"
        print("Trying: service iptables save")
        run(["service", "iptables", "save"], check=False)

    # Alpine fallback
    if have("apk"):
        print("Saving ipset for Alpine")
        # Save and create local startup hook
        with open("/etc/ipset.conf", "w") as f:
            out = subprocess.check_output(["ipset", "save"], text=True)
            f.write(out)

        os.makedirs("/etc/local.d", exist_ok=True)
        with open("/etc/local.d/ipset.start", "w") as f:
            f.write("#!/bin/sh\nipset restore < /etc/ipset.conf\n")
        os.chmod("/etc/local.d/ipset.start", 0o755)
        run(["rc-update", "add", "local"], check=False)

    # Generic fallback
    try:
        with open("/etc/ipset.conf", "w") as f:
            out = subprocess.check_output(["ipset", "save"], text=True)
            f.write(out)
    except Exception:
        pass

    print("✔ Persistence configured")

def setup_cron_persist():
    print("=== [4.5/6] Setup cron for ipset autosave/restore ===")
    cron_content = f"""# Suridash ipset auto-save and restore
*/5 * * * * root ipset save {SET_NAME} > /etc/suridash-ipset.save 2>/dev/null
@reboot root sleep 10 && ipset restore < /etc/suridash-ipset.save 2>/dev/null
"""
    try:
        with open("/etc/cron.d/suridash-ipset", "w") as f:
            f.write(cron_content)
        os.chmod("/etc/cron.d/suridash-ipset", 0o644)
        print("✔ Cron jobs for ipset created at /etc/cron.d/suridash-ipset")
    except Exception as e:
        print(f"❌ Failed to setup cron: {e}")

def test_ipset():
    print("=== [5/6] Testing ipset ===")
    try:
        run(["ipset", "list", SET_NAME], check=True)
        print("✔ ipset working")
    except subprocess.CalledProcessError:
        print("❌ ipset list failed")
        sys.exit(1)

def main():
    print("=== [0/6] Checking root permission ===")
    require_root()

    # optional: allow skip installing packages
    skip_install = os.environ.get("SURIDASH_SKIP_INSTALL", "false").lower() == "true"
    if not skip_install:
        install_packages()
    else:
        print("=== [1/6] Skipping install (SURIDASH_SKIP_INSTALL=true) ===")

    create_ipset()
    ensure_iptables_rule()
    persist_rules()
    setup_cron_persist()
    test_ipset()

    print("=== [6/6] Setup finished ===\n")
    print(f"🎉 SUCCESS! ipset '{SET_NAME}' is ready.\n")
    print("Commands you can use:")
    print(f"  ➤ Block IP:        sudo ipset add {SET_NAME} 1.2.3.4")
    print(f"  ➤ Unblock IP:      sudo ipset del {SET_NAME} 1.2.3.4")
    print(f"  ➤ View block list: sudo ipset list {SET_NAME}\n")
    print(f"Firewall automatically drops traffic from IPs in '{SET_NAME}'.")

if __name__ == "__main__":
    main()
