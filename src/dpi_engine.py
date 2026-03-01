"""
dpi_engine.py - Single-threaded DPI engine.
Mirrors main_working.cpp from the original C++ project.
"""

from __future__ import annotations
from typing import Dict, Tuple
from collections import defaultdict

from .types import (
    AppType, FiveTuple, Flow,
    ip_to_int, int_to_ip, sni_to_app_type,
)
from .pcap_reader import PcapReader, PcapWriter
from .packet_parser import PacketParser, PROTO_TCP, PROTO_UDP
from .sni_extractor import SNIExtractor, HTTPHostExtractor, DNSExtractor
from .rule_manager import RuleManager


class DPIEngine:
    """
    Read an input PCAP, classify flows using Deep Packet Inspection,
    apply blocking rules, and write allowed packets to an output PCAP.
    """

    def __init__(self, rules: RuleManager) -> None:
        self.rules = rules
        self._flows: Dict[FiveTuple, Flow] = {}
        self._total_packets   = 0
        self._forwarded       = 0
        self._dropped         = 0
        self._app_stats: Dict[AppType, int] = defaultdict(int)
        self._tcp_packets  = 0
        self._udp_packets  = 0
        self._total_bytes  = 0

    def process(self, input_path: str, output_path: str) -> None:
        """Main entry point: read input_path, write filtered output_path."""
        with PcapReader(input_path) as reader:
            with PcapWriter(output_path) as writer:
                print("[DPI] Processing packets...")
                for raw in reader.packets():
                    self._process_packet(raw, writer)

        self._print_report(output_path)

    # ── Internal ─────────────────────────────────────────────────────────────

    def _process_packet(self, raw, writer: PcapWriter) -> None:
        self._total_packets += 1
        self._total_bytes   += len(raw.data)

        parsed = PacketParser.parse(raw)
        if parsed is None or not parsed.has_ip:
            return
        if not (parsed.has_tcp or parsed.has_udp):
            return

        if parsed.has_tcp:
            self._tcp_packets += 1
        if parsed.has_udp:
            self._udp_packets += 1

        src_ip_int = ip_to_int(parsed.src_ip)
        dst_ip_int = ip_to_int(parsed.dest_ip)

        key = FiveTuple(
            src_ip=src_ip_int,
            dst_ip=dst_ip_int,
            src_port=parsed.src_port,
            dst_port=parsed.dest_port,
            protocol=parsed.protocol,
        )

        # Get or create flow
        if key not in self._flows:
            self._flows[key] = Flow(tuple=key)
        flow = self._flows[key]
        flow.packets += 1
        flow.bytes_  += len(raw.data)

        payload = parsed.payload_data

        # ── TLS/HTTPS SNI extraction (port 443) ──────────────────────────────
        if (parsed.has_tcp and parsed.dest_port == 443 and
                not flow.sni and len(payload) > 5):
            sni = SNIExtractor.extract(payload)
            if sni:
                flow.sni      = sni
                flow.app_type = sni_to_app_type(sni)

        # ── HTTP Host extraction (port 80) ────────────────────────────────────
        if (parsed.has_tcp and parsed.dest_port == 80 and
                not flow.sni and len(payload) > 4):
            host = HTTPHostExtractor.extract(payload)
            if host:
                flow.sni      = host
                flow.app_type = sni_to_app_type(host)

        # ── DNS classification (port 53) ──────────────────────────────────────
        if (flow.app_type == AppType.UNKNOWN and
                (parsed.dest_port == 53 or parsed.src_port == 53)):
            flow.app_type = AppType.DNS

        # ── Port-based fallback ───────────────────────────────────────────────
        if flow.app_type == AppType.UNKNOWN:
            if parsed.dest_port == 443:
                flow.app_type = AppType.HTTPS
            elif parsed.dest_port == 80:
                flow.app_type = AppType.HTTP

        # ── Blocking rules ────────────────────────────────────────────────────
        if not flow.blocked:
            if self.rules.is_blocked(src_ip_int, flow.app_type, flow.sni):
                flow.blocked = True
                label = flow.app_type.value
                detail = f": {flow.sni}" if flow.sni else ""
                print(f"[BLOCKED] {parsed.src_ip} -> {parsed.dest_ip} ({label}{detail})")

        self._app_stats[flow.app_type] += 1

        # ── Forward or drop ───────────────────────────────────────────────────
        if flow.blocked:
            self._dropped += 1
        else:
            self._forwarded += 1
            writer.write_packet(raw)

    # ── Reporting ─────────────────────────────────────────────────────────────

    def _print_report(self, output_path: str) -> None:
        W = 66

        def row(label: str, value) -> str:
            return f"║ {label:<30}{str(value):>12}{'':>22}║"

        print()
        print("╔" + "═" * W + "╗")
        print("║" + "  PROCESSING REPORT  ".center(W) + "║")
        print("╠" + "═" * W + "╣")
        print(f"║  {'Total Packets:':<28}{self._total_packets:>10}{'':>26}║")
        print(f"║  {'Total Bytes:':<28}{self._total_bytes:>10}{'':>26}║")
        print(f"║  {'TCP Packets:':<28}{self._tcp_packets:>10}{'':>26}║")
        print(f"║  {'UDP Packets:':<28}{self._udp_packets:>10}{'':>26}║")
        print(f"║  {'Active Flows:':<28}{len(self._flows):>10}{'':>26}║")
        print("╠" + "═" * W + "╣")
        print(f"║  {'Forwarded:':<28}{self._forwarded:>10}{'':>26}║")
        print(f"║  {'Dropped:':<28}{self._dropped:>10}{'':>26}║")
        print("╠" + "═" * W + "╣")
        print("║" + "  APPLICATION BREAKDOWN  ".center(W) + "║")
        print("╠" + "═" * W + "╣")

        sorted_apps = sorted(self._app_stats.items(), key=lambda x: -x[1])
        for app, count in sorted_apps:
            pct = 100.0 * count / max(self._total_packets, 1)
            bar = "#" * int(pct / 5)
            blocked_tag = " (BLOCKED)" if app in self.rules._blocked_apps else ""
            line = f"  {app.value + blocked_tag:<22}{count:>6}  {pct:>5.1f}%  {bar}"
            print(f"║{line:<{W}}║")

        print("╚" + "═" * W + "╝")

        # Unique SNIs
        print("\n[Detected Domains / SNIs]")
        seen: Dict[str, AppType] = {}
        for flow in self._flows.values():
            if flow.sni:
                seen[flow.sni] = flow.app_type
        for sni, app in sorted(seen.items()):
            print(f"  - {sni} -> {app.value}")

        print(f"\nOutput written to: {output_path}")
