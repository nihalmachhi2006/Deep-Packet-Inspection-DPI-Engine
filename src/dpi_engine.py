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
        with PcapReader(input_path) as reader:
            with PcapWriter(output_path) as writer:
                print("Processing packets...")
                for raw in reader.packets():
                    self._process_packet(raw, writer)

        self._print_report(output_path)

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

        if key not in self._flows:
            self._flows[key] = Flow(tuple=key)
        flow = self._flows[key]
        flow.packets += 1
        flow.bytes_  += len(raw.data)

        payload = parsed.payload_data

        if (parsed.has_tcp and parsed.dest_port == 443 and
                not flow.sni and len(payload) > 5):
            sni = SNIExtractor.extract(payload)
            if sni:
                flow.sni      = sni
                flow.app_type = sni_to_app_type(sni)

        if (parsed.has_tcp and parsed.dest_port == 80 and
                not flow.sni and len(payload) > 4):
            host = HTTPHostExtractor.extract(payload)
            if host:
                flow.sni      = host
                flow.app_type = sni_to_app_type(host)

        if (flow.app_type == AppType.UNKNOWN and
                (parsed.dest_port == 53 or parsed.src_port == 53)):
            flow.app_type = AppType.DNS

        if flow.app_type == AppType.UNKNOWN:
            if parsed.dest_port == 443:
                flow.app_type = AppType.HTTPS
            elif parsed.dest_port == 80:
                flow.app_type = AppType.HTTP

        if not flow.blocked:
            if self.rules.is_blocked(src_ip_int, flow.app_type, flow.sni):
                flow.blocked = True
                label = flow.app_type.value
                detail = f": {flow.sni}" if flow.sni else ""
                print(f"[BLOCKED] {parsed.src_ip} -> {parsed.dest_ip} ({label}{detail})")

        self._app_stats[flow.app_type] += 1

        if flow.blocked:
            self._dropped += 1
        else:
            self._forwarded += 1
            writer.write_packet(raw)

    def _print_report(self, output_path: str) -> None:

        print()
        print("Processing report")
        print(f"Total packets: {self._total_packets}")
        print(f"Total bytes: {self._total_bytes}")
        print(f"TCP packets: {self._tcp_packets}")
        print(f"UDP packets: {self._udp_packets}")
        print(f"Active flows: {len(self._flows)}")
        print(f"Forwarded: {self._forwarded}")
        print(f"Dropped: {self._dropped}")
        print("Application breakdown")

        sorted_apps = sorted(self._app_stats.items(), key=lambda x: -x[1])
        for app, count in sorted_apps:
            pct = 100.0 * count / max(self._total_packets, 1)
            bar = "#" * int(pct / 5)
            blocked_tag = " (BLOCKED)" if app in self.rules._blocked_apps else ""
            line = f"  {app.value + blocked_tag:<22}{count:>6}  {pct:>5.1f}%  {bar}"
            print(line)

        print()
        print("Detected domains / SNIs")
        seen: Dict[str, AppType] = {}
        for flow in self._flows.values():
            if flow.sni:
                seen[flow.sni] = flow.app_type
        for sni, app in sorted(seen.items()):
            print(f"{sni} -> {app.value}")

        print(f"\nOutput written to: {output_path}")
