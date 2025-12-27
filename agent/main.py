import argparse
from agent.core.agent import Agent
from agent.setup.firewall import setup_firewall

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Initial system setup (iptables, ipset)"
    )

    args = parser.parse_args()

    if args.setup:
        setup_firewall()
        print("✅ Firewall setup completed")
        return

    agent = Agent()
    agent.run()

if __name__ == "__main__":
    main()
