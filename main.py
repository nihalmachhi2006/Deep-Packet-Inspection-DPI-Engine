#!/usr/bin/env python3

import sys
import argparse

from src.rule_manager import RuleManager
from src.dpi_engine import DPIEngine
from src.dpi_engine_mt import MTDPIEngine


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dpi_engine", description="Deep Packet Inspection Engine")
    p.add_argument("input",  help="Input PCAP file")
    p.add_argument("output", help="Output PCAP file (filtered)")

    p.add_argument("--block-ip",     action="append", default=[], metavar="IP",
                   help="Block traffic from source IP (can repeat)")
    p.add_argument("--block-app",    action="append", default=[], metavar="APP",
                   help="Block app by name (YouTube, Facebook, TikTok, …)")
    p.add_argument("--block-domain", action="append", default=[], metavar="DOMAIN",
                   help="Block domain substring (e.g. 'tiktok')")

    p.add_argument("--mt",  action="store_true", help="Use multi-threaded engine")
    p.add_argument("--lbs", type=int, default=2, metavar="N",
                   help="Load Balancer thread count [default: 2]")
    p.add_argument("--fps", type=int, default=2, metavar="N",
                   help="Fast Path threads per LB [default: 2]")

    return p


def main() -> int:
    args = build_parser().parse_args()

    mode = "Multi-threaded" if args.mt else "Single-threaded"
    print(f"DPI Engine v2.0 ({mode})")
    print()

    rules = RuleManager()
    for ip in args.block_ip:
        rules.block_ip(ip)
    for app in args.block_app:
        rules.block_app(app)
    for domain in args.block_domain:
        rules.block_domain(domain)
    if rules.has_rules:
        print()

    try:
        if args.mt:
            engine = MTDPIEngine(rules, num_lbs=args.lbs, fps_per_lb=args.fps)
        else:
            engine = DPIEngine(rules)
        engine.process(args.input, args.output)
    except FileNotFoundError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
