#!/usr/bin/env python3

import struct
import random
import sys

def pcap_global_header() -> bytes:
    return struct.pack("<IHHiIII",
        0xA1B2C3D4,
        2, 4,
        0,
        0,
        65535,
        1,
    )


def pcap_packet_header(ts_sec: int, ts_usec: int, length: int) -> bytes:
    return struct.pack("<IIII", ts_sec, ts_usec, length, length)


def eth_header(src_mac: bytes, dst_mac: bytes, ethertype: int = 0x0800) -> bytes:
    return dst_mac + src_mac + struct.pack("!H", ethertype)


def ip_header(src_ip: str, dst_ip: str, proto: int, payload_len: int) -> bytes:
    def pton(ip: str) -> bytes:
        return bytes(int(x) for x in ip.split("."))

    total_len = 20 + payload_len
    hdr = struct.pack("!BBHHHBBH",
        0x45,
        0,
        total_len,
        random.randint(1, 65535),
        0,
        64,
        proto,
        0,
    ) + pton(src_ip) + pton(dst_ip)
    return hdr


def tcp_header(sport: int, dport: int, flags: int = 0x02, seq: int = 0) -> bytes:
    return struct.pack("!HHIIBBHH",
        sport, dport,
        seq,
        0,
        0x50,
        flags,
        65535,
        0,
    ) + struct.pack("!H", 0)


def udp_header(sport: int, dport: int, payload_len: int) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + payload_len, 0)

def tls_client_hello(sni: str) -> bytes:
    sni_bytes = sni.encode()
    sni_len   = len(sni_bytes)

    sni_ext_data = (
        struct.pack("!H", sni_len + 3) +
        b"\x00" +
        struct.pack("!H", sni_len) +
        sni_bytes
    )
    sni_extension = struct.pack("!HH", 0x0000, len(sni_ext_data)) + sni_ext_data

    sv_ext = struct.pack("!HHHB", 0x002B, 3, 2, 0x03) + b"\x04"

    extensions = sni_extension + sv_ext
    extensions_block = struct.pack("!H", len(extensions)) + extensions

    body = (
        b"\x03\x03"
        + bytes(random.getrandbits(8) for _ in range(32))
        + b"\x00"
        + struct.pack("!H", 4) + b"\xc0\x2b\xc0\x2f"
        + b"\x01\x00"
        + extensions_block
    )

    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body

    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake

def dns_query(domain: str) -> bytes:
    qname = b""
    for label in domain.split("."):
        lb = label.encode()
        qname += bytes([len(lb)]) + lb
    qname += b"\x00"

    return struct.pack("!HHHHHH",
        random.randint(1, 65535),
        0x0100,
        1, 0, 0, 0,
    ) + qname + struct.pack("!HH", 1, 1)

def http_request(host: str, path: str = "/") -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: TestBrowser/1.0\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    ).encode()

_SRC_MAC  = bytes.fromhex("001122334455")
_DST_MAC  = bytes.fromhex("aabbccddeeff")
_GW_MAC   = bytes.fromhex("aabbccddeeff")


def make_tcp_tls_packet(src_ip: str, dst_ip: str, sport: int, dport: int,
                         payload: bytes, ts: int) -> bytes:
    tcp = tcp_header(sport, dport, flags=0x18)
    ip  = ip_header(src_ip, dst_ip, 6, len(tcp) + len(payload))
    eth = eth_header(_SRC_MAC, _DST_MAC)
    frame = eth + ip + tcp + payload
    return pcap_packet_header(ts, 0, len(frame)) + frame


def make_udp_packet(src_ip: str, dst_ip: str, sport: int, dport: int,
                     payload: bytes, ts: int) -> bytes:
    udp  = udp_header(sport, dport, len(payload))
    ip   = ip_header(src_ip, dst_ip, 17, len(udp) + len(payload))
    eth  = eth_header(_SRC_MAC, _DST_MAC)
    frame = eth + ip + udp + payload
    return pcap_packet_header(ts, 0, len(frame)) + frame

SCENARIOS = [
    ("192.168.1.100", "142.250.185.206", "tls",  "www.youtube.com",   8, "YouTube HTTPS"),
    ("192.168.1.101", "157.240.229.35",  "tls",  "www.facebook.com",  5, "Facebook HTTPS"),
    ("192.168.1.102", "8.8.8.8",         "dns",  "google.com",        4, "DNS lookup"),
    ("192.168.1.103", "93.184.216.34",   "http", "example.com",       3, "HTTP request"),
    ("192.168.1.104", "151.101.1.140",   "tls",  "github.com",        6, "GitHub HTTPS"),
    ("192.168.1.105", "149.154.167.51",  "tls",  "telegram.org",      4, "Telegram HTTPS"),
    ("192.168.1.106", "31.13.92.36",     "tls",  "www.instagram.com", 5, "Instagram HTTPS"),
    ("192.168.1.107", "199.232.64.78",   "tls",  "open.spotify.com",  4, "Spotify HTTPS"),
    ("192.168.1.108", "13.32.99.14",     "tls",  "www.amazon.com",    5, "Amazon HTTPS"),
    ("192.168.1.109", "185.94.192.17",   "tls",  "discord.com",       4, "Discord HTTPS"),
    ("192.168.1.50",  "104.18.25.35",    "tls",  "www.tiktok.com",    5, "TikTok (blocked IP)"),
    ("192.168.1.110", "18.160.0.52",     "tls",  "zoom.us",           3, "Zoom HTTPS"),
    ("192.168.1.111", "8.8.8.8",         "dns",  "netflix.com",       2, "DNS lookup Netflix"),
    ("192.168.1.112", "140.82.112.4",    "tls",  "api.github.com",    3, "GitHub API"),
    ("192.168.1.113", "23.195.0.0",      "tls",  "www.apple.com",     3, "Apple HTTPS"),
]


def generate(output_path: str) -> None:
    packets = [pcap_global_header()]
    ts = 1_700_000_000
    total = 0

    for (src_ip, dst_ip, proto, host, count, desc) in SCENARIOS:
        print(f"  Generating {count} packets: {desc}")
        sport = random.randint(49152, 65535)

        for i in range(count):
            ts += 1

            if proto == "tls":
                if i == 0:
                    payload = tls_client_hello(host)
                else:
                    payload = bytes(random.getrandbits(8) for _ in range(random.randint(50, 200)))
                pkt = make_tcp_tls_packet(src_ip, dst_ip, sport, 443, payload, ts)

            elif proto == "http":
                payload = http_request(host) if i == 0 else b"HTTP/1.1 200 OK\r\n\r\n"
                pkt = make_tcp_tls_packet(src_ip, dst_ip, sport, 80, payload, ts)

            elif proto == "dns":
                payload = dns_query(host)
                pkt = make_udp_packet(src_ip, "8.8.8.8", sport, 53, payload, ts)

            else:
                continue

            packets.append(pkt)
            total += 1

    data = b"".join(packets)
    with open(output_path, "wb") as f:
        f.write(data)

    print(f"Generated {total} packets -> {output_path}")
    print(f"  File size: {len(data):,} bytes")


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "test_dpi.pcap"
    print(f"Generating test PCAP: {out}")
    generate(out)
