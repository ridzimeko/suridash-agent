import argparse

def main():
    p = argparse.ArgumentParser(prog="suridash-agent")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("setup", help="Setup ipset/iptables (requires root)")
    sub.add_parser("run", help="Run Suridash agent")
    
    update_parser = sub.add_parser("update", help="Update Suridash agent via dashboard script")
    update_parser.add_argument("version", nargs="?", default="latest", help="Target version to update (default: latest)")

    args = p.parse_args()

    if args.cmd == "setup":
        from agent.setup import main as setup_main
        setup_main()

    elif args.cmd == "run":
        from agent.main import main as run_main
        run_main()

    elif args.cmd == "update":
        from agent.update import main as update_main
        update_main(args.version)

if __name__ == "__main__":
    main()
