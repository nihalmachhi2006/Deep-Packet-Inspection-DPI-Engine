from __future__ import annotations

import threading
import queue
import hashlib
import struct
from collections import defaultdict
from typing import Dict, List, Optional

from .types import (
    AppType, FiveTuple, Flow,
    ip_to_int, sni_to_app_type,
)
from .pcap_reader import PcapReader, PcapWriter
from .packet_parser import PacketParser
from .sni_extractor import SNIExtractor, HTTPHostExtractor
from .rule_manager import RuleManager

_SENTINEL = None


def _hash_tuple(t: FiveTuple) -> int:
    packed = struct.pack("!IIHHB", t.src_ip, t.dst_ip, t.src_port, t.dst_port, t.protocol)
    return int(hashlib.md5(packed).hexdigest(), 16)


class _Stats:
    def __init__(self) -> None:
        self._lock         = threading.Lock()
        self.total         = 0
        self.forwarded     = 0
        self.dropped       = 0
        self.tcp           = 0
        self.udp           = 0
        self.total_bytes   = 0
        self.app_counts: Dict[AppType, int] = defaultdict(int)
        self.lb_dispatched: Dict[int, int]  = defaultdict(int)
        self.fp_processed:  Dict[int, int]  = defaultdict(int)

    def add(self, **kwargs) -> None:
        with self._lock:
            for k, v in kwargs.items():
                if k == "app":
                    self.app_counts[v] += 1
                elif k == "lb":
                    self.lb_dispatched[v] += 1
                elif k == "fp":
                    self.fp_processed[v] += 1
                else:
                    setattr(self, k, getattr(self, k) + v)


class MTDPIEngine:
    def __init__(self,
                 rules: RuleManager,
                 num_lbs: int = 2,
                 fps_per_lb: int = 2) -> None:
        self.rules      = rules
        self.num_lbs    = num_lbs
        self.fps_per_lb = fps_per_lb
        self._stats     = _Stats()

    def process(self, input_path: str, output_path: str) -> None:
        total_fps = self.num_lbs * self.fps_per_lb

        print("DPI Engine v2.0 (Multi-threaded)")
        print(f"Load balancers: {self.num_lbs}")
        print(f"FPs per LB: {self.fps_per_lb}")
        print(f"Total FPs: {total_fps}")
        print()

        lb_queues: List[queue.Queue] = [queue.Queue(maxsize=10_000) for _ in range(self.num_lbs)]
        fp_queues: List[List[queue.Queue]] = [
            [queue.Queue(maxsize=10_000) for _ in range(self.fps_per_lb)]
            for _ in range(self.num_lbs)
        ]
        output_queue: queue.Queue = queue.Queue(maxsize=20_000)

        flow_tables: List[Dict[FiveTuple, Flow]] = [{} for _ in range(total_fps)]

        writer_done = threading.Event()
        writer_thread = threading.Thread(
            target=self._output_writer,
            args=(output_path, output_queue, writer_done),
            daemon=True, name="OutputWriter"
        )
        writer_thread.start()

        fp_threads: List[threading.Thread] = []
        fp_id = 0
        for lb_idx in range(self.num_lbs):
            for fp_idx in range(self.fps_per_lb):
                t = threading.Thread(
                    target=self._fast_path_worker,
                    args=(fp_id, fp_queues[lb_idx][fp_idx],
                          flow_tables[fp_id], output_queue),
                    daemon=True, name=f"FP-{fp_id}"
                )
                t.start()
                fp_threads.append(t)
                fp_id += 1

        lb_threads: List[threading.Thread] = []
        for lb_idx in range(self.num_lbs):
            t = threading.Thread(
                target=self._lb_worker,
                args=(lb_idx, lb_queues[lb_idx], fp_queues[lb_idx]),
                daemon=True, name=f"LB-{lb_idx}"
            )
            t.start()
            lb_threads.append(t)

        print("Processing packets...")
        with PcapReader(input_path) as reader:
            for raw in reader.packets():
                self._stats.add(total=1, total_bytes=len(raw.data))

                parsed = PacketParser.parse(raw)
                if parsed is None or not parsed.has_ip:
                    continue
                if not (parsed.has_tcp or parsed.has_udp):
                    continue

                if parsed.has_tcp:
                    self._stats.add(tcp=1)
                if parsed.has_udp:
                    self._stats.add(udp=1)

                src_ip_int = ip_to_int(parsed.src_ip)
                dst_ip_int = ip_to_int(parsed.dest_ip)
                key = FiveTuple(src_ip_int, dst_ip_int,
                                parsed.src_port, parsed.dest_port,
                                parsed.protocol)

                lb_idx = _hash_tuple(key) % self.num_lbs
                self._stats.add(lb=lb_idx)
                lb_queues[lb_idx].put((raw, parsed, key))

            print(f"Done reading {self._stats.total} packets")

        for q in lb_queues:
            q.put(_SENTINEL)
        for t in lb_threads:
            t.join()

        for lb_idx in range(self.num_lbs):
            for q in fp_queues[lb_idx]:
                q.put(_SENTINEL)
        for t in fp_threads:
            t.join()

        output_queue.put(_SENTINEL)
        writer_thread.join()

        self._print_report(output_path, flow_tables)

    def _lb_worker(self, lb_idx: int,
                   in_q: queue.Queue,
                   fp_qs: List[queue.Queue]) -> None:
        num_fps = len(fp_qs)
        while True:
            item = in_q.get()
            if item is _SENTINEL:
                break
            raw, parsed, key = item
            fp_idx = _hash_tuple(key) % num_fps
            self._stats.add(lb=lb_idx)
            fp_qs[fp_idx].put((raw, parsed, key))

    def _fast_path_worker(self,
                          fp_id: int,
                          in_q: queue.Queue,
                          flows: Dict[FiveTuple, Flow],
                          out_q: queue.Queue) -> None:
        while True:
            item = in_q.get()
            if item is _SENTINEL:
                break

            raw, parsed, key = item
            self._stats.add(fp=fp_id)

            if key not in flows:
                flows[key] = Flow(tuple=key)
            flow = flows[key]
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

            src_ip_int = ip_to_int(parsed.src_ip)

            if not flow.blocked:
                if self.rules.is_blocked(src_ip_int, flow.app_type, flow.sni):
                    flow.blocked = True
                    detail = f": {flow.sni}" if flow.sni else ""
                    print(f"[BLOCKED] {parsed.src_ip} -> {parsed.dest_ip} "
                          f"({flow.app_type.value}{detail})")

            self._stats.add(app=flow.app_type)

            if flow.blocked:
                self._stats.add(dropped=1)
            else:
                self._stats.add(forwarded=1)
                out_q.put(raw)

    def _output_writer(self, output_path: str,
                       out_q: queue.Queue,
                       done_event: threading.Event) -> None:
        with PcapWriter(output_path) as writer:
            while True:
                item = out_q.get()
                if item is _SENTINEL:
                    break
                writer.write_packet(item)
        done_event.set()

    def _print_report(self, output_path: str,
                      flow_tables: List[Dict]) -> None:
        s = self._stats

        print()
        print("Processing report")
        print(f"Total packets: {s.total}")
        print(f"Total bytes: {s.total_bytes}")
        print(f"TCP packets: {s.tcp}")
        print(f"UDP packets: {s.udp}")
        print(f"Forwarded: {s.forwarded}")
        print(f"Dropped: {s.dropped}")
        print("Thread statistics")
        for lb_idx in range(self.num_lbs):
            cnt = s.lb_dispatched.get(lb_idx, 0)
            print(f"LB{lb_idx} dispatched: {cnt}")
        fp_id = 0
        for lb_idx in range(self.num_lbs):
            for _ in range(self.fps_per_lb):
                cnt = s.fp_processed.get(fp_id, 0)
                print(f"FP{fp_id} processed: {cnt}")
                fp_id += 1
        print("Application breakdown")
        sorted_apps = sorted(s.app_counts.items(), key=lambda x: -x[1])
        for app, count in sorted_apps:
            pct = 100.0 * count / max(s.total, 1)
            bar = "#" * int(pct / 5)
            blocked = " (BLOCKED)" if app in self.rules._blocked_apps else ""
            line = f"  {app.value + blocked:<22}{count:>6}  {pct:>5.1f}%  {bar}"
            print(line)
        print()
        print("Detected domains / SNIs")
        seen: Dict[str, AppType] = {}
        for ft in flow_tables:
            for flow in ft.values():
                if flow.sni:
                    seen[flow.sni] = flow.app_type
        for sni, app in sorted(seen.items()):
            print(f"{sni} -> {app.value}")

        print(f"\nOutput written to: {output_path}")
