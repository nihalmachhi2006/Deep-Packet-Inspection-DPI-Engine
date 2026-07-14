from __future__ import annotations
import struct

from .types import ParsedPacket, RawPacket

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP  = 0x0806

PROTO_ICMP = 1
PROTO_TCP  = 6
PROTO_UDP  = 17

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20


def _mac_to_str(data: bytes, offset: int = 0) -> str:
    return ":".join(f"{b:02x}" for b in data[offset:offset + 6])


def _ip_to_str(data: bytes, offset: int = 0) -> str:
    return ".".join(str(b) for b in data[offset:offset + 4])


def tcp_flags_to_str(flags: int) -> str:
    parts = []
    if flags & TCP_SYN: parts.append("SYN")
    if flags & TCP_ACK: parts.append("ACK")
    if flags & TCP_FIN: parts.append("FIN")
    if flags & TCP_RST: parts.append("RST")
    if flags & TCP_PSH: parts.append("PSH")
    if flags & TCP_URG: parts.append("URG")
    return " ".join(parts) or "none"


class PacketParser:
    @staticmethod
    def parse(raw: RawPacket) -> ParsedPacket | None:
        parsed = ParsedPacket(
            timestamp_sec=raw.header.ts_sec,
            timestamp_usec=raw.header.ts_usec,
        )
        data = raw.data
        offset = 0

        if len(data) < 14:
            return None

        parsed.dest_mac  = _mac_to_str(data, 0)
        parsed.src_mac   = _mac_to_str(data, 6)
        parsed.ether_type = struct.unpack_from("!H", data, 12)[0]
        offset = 14

        if parsed.ether_type != ETHERTYPE_IPV4:
            return parsed

        if len(data) < offset + 20:
            return None

        version_ihl = data[offset]
        parsed.ip_version = (version_ihl >> 4) & 0x0F
        ihl = (version_ihl & 0x0F) * 4

        if parsed.ip_version != 4 or ihl < 20:
            return None
        if len(data) < offset + ihl:
            return None

        parsed.ttl      = data[offset + 8]
        parsed.protocol = data[offset + 9]
        parsed.src_ip   = _ip_to_str(data, offset + 12)
        parsed.dest_ip  = _ip_to_str(data, offset + 16)
        parsed.has_ip   = True
        offset += ihl

        if parsed.protocol == PROTO_TCP:
            if len(data) < offset + 20:
                return parsed

            parsed.src_port  = struct.unpack_from("!H", data, offset)[0]
            parsed.dest_port = struct.unpack_from("!H", data, offset + 2)[0]
            parsed.seq_number = struct.unpack_from("!I", data, offset + 4)[0]
            parsed.ack_number = struct.unpack_from("!I", data, offset + 8)[0]
            data_offset = (data[offset + 12] >> 4) & 0x0F
            tcp_hdr_len = data_offset * 4
            parsed.tcp_flags = data[offset + 13]
            parsed.has_tcp   = True

            if tcp_hdr_len < 20 or len(data) < offset + tcp_hdr_len:
                return parsed
            offset += tcp_hdr_len

        elif parsed.protocol == PROTO_UDP:
            if len(data) < offset + 8:
                return parsed

            parsed.src_port  = struct.unpack_from("!H", data, offset)[0]
            parsed.dest_port = struct.unpack_from("!H", data, offset + 2)[0]
            parsed.has_udp   = True
            offset += 8

        parsed.payload_data   = data[offset:]
        parsed.payload_length = len(parsed.payload_data)

        return parsed
