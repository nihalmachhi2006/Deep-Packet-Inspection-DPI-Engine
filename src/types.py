from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
import struct

class AppType(Enum):
    UNKNOWN    = "Unknown"
    HTTP       = "HTTP"
    HTTPS      = "HTTPS"
    DNS        = "DNS"
    TLS        = "TLS"
    QUIC       = "QUIC"
    GOOGLE     = "Google"
    FACEBOOK   = "Facebook"
    YOUTUBE    = "YouTube"
    TWITTER    = "Twitter/X"
    INSTAGRAM  = "Instagram"
    NETFLIX    = "Netflix"
    AMAZON     = "Amazon"
    MICROSOFT  = "Microsoft"
    APPLE      = "Apple"
    WHATSAPP   = "WhatsApp"
    TELEGRAM   = "Telegram"
    TIKTOK     = "TikTok"
    SPOTIFY    = "Spotify"
    ZOOM       = "Zoom"
    DISCORD    = "Discord"
    GITHUB     = "GitHub"
    CLOUDFLARE = "Cloudflare"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class FiveTuple:
    src_ip:   int
    dst_ip:   int
    src_port: int
    dst_port: int
    protocol: int

    def __str__(self) -> str:
        return (
            f"{int_to_ip(self.src_ip)}:{self.src_port} -> "
            f"{int_to_ip(self.dst_ip)}:{self.dst_port} "
            f"({'TCP' if self.protocol == 6 else 'UDP' if self.protocol == 17 else str(self.protocol)})"
        )


@dataclass
class Flow:
    tuple:     FiveTuple = None
    app_type:  AppType   = AppType.UNKNOWN
    sni:       str       = ""
    packets:   int       = 0
    bytes_:    int       = 0
    blocked:   bool      = False


@dataclass
class PcapGlobalHeader:
    magic_number:   int
    version_major:  int
    version_minor:  int
    thiszone:       int
    sigfigs:        int
    snaplen:        int
    network:        int

    STRUCT = struct.Struct("<IHHiIII")
    SIZE   = STRUCT.size

    @classmethod
    def from_bytes(cls, data: bytes) -> "PcapGlobalHeader":
        fields = cls.STRUCT.unpack(data[:cls.SIZE])
        return cls(*fields)

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(
            self.magic_number, self.version_major, self.version_minor,
            self.thiszone, self.sigfigs, self.snaplen, self.network
        )


@dataclass
class PcapPacketHeader:
    ts_sec:    int
    ts_usec:   int
    incl_len:  int
    orig_len:  int

    STRUCT = struct.Struct("<IIII")
    SIZE   = STRUCT.size

    @classmethod
    def from_bytes(cls, data: bytes) -> "PcapPacketHeader":
        fields = cls.STRUCT.unpack(data[:cls.SIZE])
        return cls(*fields)

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(
            self.ts_sec, self.ts_usec, self.incl_len, self.orig_len
        )


@dataclass
class RawPacket:
    header: PcapPacketHeader
    data:   bytes


@dataclass
class ParsedPacket:
    timestamp_sec:  int = 0
    timestamp_usec: int = 0
    src_mac:   str = ""
    dest_mac:  str = ""
    ether_type: int = 0
    has_ip:     bool = False
    ip_version: int  = 0
    src_ip:     str  = ""
    dest_ip:    str  = ""
    ttl:        int  = 0
    protocol:   int  = 0
    has_tcp:    bool = False
    src_port:   int  = 0
    dest_port:  int  = 0
    seq_number: int  = 0
    ack_number: int  = 0
    tcp_flags:  int  = 0
    has_udp:    bool = False
    payload_data:   bytes = b""
    payload_length: int   = 0


def int_to_ip(n: int) -> str:
    return f"{n & 0xFF}.{(n >> 8) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 24) & 0xFF}"


def ip_to_int(ip: str) -> int:
    parts = ip.split(".")
    result = 0
    for shift, part in enumerate(parts):
        result |= int(part) << (shift * 8)
    return result


def sni_to_app_type(sni: str) -> AppType:
    if not sni:
        return AppType.UNKNOWN

    s = sni.lower()

    if any(k in s for k in ("youtube", "ytimg", "youtu.be", "yt3.ggpht")):
        return AppType.YOUTUBE

    if any(k in s for k in ("google", "gstatic", "googleapis", "ggpht", "gvt1")):
        return AppType.GOOGLE

    if any(k in s for k in ("facebook", "fbcdn", "fb.com", "fbsbx", "meta.com")):
        return AppType.FACEBOOK

    if any(k in s for k in ("instagram", "cdninstagram")):
        return AppType.INSTAGRAM

    if any(k in s for k in ("whatsapp", "wa.me")):
        return AppType.WHATSAPP

    if any(k in s for k in ("twitter", "twimg", "x.com", "t.co")):
        return AppType.TWITTER

    if any(k in s for k in ("netflix", "nflxvideo", "nflximg")):
        return AppType.NETFLIX

    if any(k in s for k in ("amazon", "amazonaws", "cloudfront", "aws")):
        return AppType.AMAZON

    if any(k in s for k in ("microsoft", "msn.com", "office", "azure",
                              "live.com", "outlook", "bing")):
        return AppType.MICROSOFT

    if any(k in s for k in ("apple", "icloud", "mzstatic", "itunes")):
        return AppType.APPLE

    if any(k in s for k in ("telegram", "t.me")):
        return AppType.TELEGRAM

    if any(k in s for k in ("tiktok", "tiktokcdn", "musical.ly", "bytedance")):
        return AppType.TIKTOK

    if any(k in s for k in ("spotify", "scdn.co")):
        return AppType.SPOTIFY

    if "zoom" in s:
        return AppType.ZOOM

    if any(k in s for k in ("discord", "discordapp")):
        return AppType.DISCORD

    if any(k in s for k in ("github", "githubusercontent")):
        return AppType.GITHUB

    if any(k in s for k in ("cloudflare", "cf-")):
        return AppType.CLOUDFLARE

    return AppType.HTTPS
