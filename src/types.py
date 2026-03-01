"""
types.py - Core data structures and enumerations for the DPI Engine.
Mirrors types.h / types.cpp from the original C++ project.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional
import struct


# ──────────────────────────────────────────────────────────────────────────────
# Enumerations
# ──────────────────────────────────────────────────────────────────────────────

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


# ──────────────────────────────────────────────────────────────────────────────
# Data Structures
# ──────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class FiveTuple:
    """Unique identifier for a network connection/flow."""
    src_ip:   int   # 32-bit integer
    dst_ip:   int   # 32-bit integer
    src_port: int   # 16-bit integer
    dst_port: int   # 16-bit integer
    protocol: int   # 8-bit integer (6=TCP, 17=UDP)

    def __str__(self) -> str:
        return (
            f"{int_to_ip(self.src_ip)}:{self.src_port} -> "
            f"{int_to_ip(self.dst_ip)}:{self.dst_port} "
            f"({'TCP' if self.protocol == 6 else 'UDP' if self.protocol == 17 else str(self.protocol)})"
        )


@dataclass
class Flow:
    """Tracks state for a single network connection."""
    tuple:     FiveTuple = None
    app_type:  AppType   = AppType.UNKNOWN
    sni:       str       = ""
    packets:   int       = 0
    bytes_:    int       = 0
    blocked:   bool      = False


@dataclass
class PcapGlobalHeader:
    magic_number:   int  # 0xa1b2c3d4
    version_major:  int
    version_minor:  int
    thiszone:       int
    sigfigs:        int
    snaplen:        int
    network:        int  # 1 = Ethernet

    STRUCT = struct.Struct("<IHHiIII")
    SIZE   = STRUCT.size  # 24 bytes

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
    SIZE   = STRUCT.size  # 16 bytes

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
    # Timestamps
    timestamp_sec:  int = 0
    timestamp_usec: int = 0
    # Ethernet
    src_mac:   str = ""
    dest_mac:  str = ""
    ether_type: int = 0
    # IP
    has_ip:     bool = False
    ip_version: int  = 0
    src_ip:     str  = ""
    dest_ip:    str  = ""
    ttl:        int  = 0
    protocol:   int  = 0
    # TCP
    has_tcp:    bool = False
    src_port:   int  = 0
    dest_port:  int  = 0
    seq_number: int  = 0
    ack_number: int  = 0
    tcp_flags:  int  = 0
    # UDP
    has_udp:    bool = False
    # Payload
    payload_data:   bytes = b""
    payload_length: int   = 0


# ──────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ──────────────────────────────────────────────────────────────────────────────

def int_to_ip(n: int) -> str:
    """Convert a 32-bit little-endian integer to dotted-decimal IP string."""
    return f"{n & 0xFF}.{(n >> 8) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 24) & 0xFF}"


def ip_to_int(ip: str) -> int:
    """Convert dotted-decimal IP string to 32-bit little-endian integer."""
    parts = ip.split(".")
    result = 0
    for shift, part in enumerate(parts):
        result |= int(part) << (shift * 8)
    return result


def sni_to_app_type(sni: str) -> AppType:
    """Map an SNI/domain string to an AppType."""
    if not sni:
        return AppType.UNKNOWN

    s = sni.lower()

    # YouTube (before Google so 'youtube.com' matches YouTube, not Google)
    if any(k in s for k in ("youtube", "ytimg", "youtu.be", "yt3.ggpht")):
        return AppType.YOUTUBE

    # Google
    if any(k in s for k in ("google", "gstatic", "googleapis", "ggpht", "gvt1")):
        return AppType.GOOGLE

    # Facebook / Meta
    if any(k in s for k in ("facebook", "fbcdn", "fb.com", "fbsbx", "meta.com")):
        return AppType.FACEBOOK

    # Instagram
    if any(k in s for k in ("instagram", "cdninstagram")):
        return AppType.INSTAGRAM

    # WhatsApp
    if any(k in s for k in ("whatsapp", "wa.me")):
        return AppType.WHATSAPP

    # Twitter / X
    if any(k in s for k in ("twitter", "twimg", "x.com", "t.co")):
        return AppType.TWITTER

    # Netflix
    if any(k in s for k in ("netflix", "nflxvideo", "nflximg")):
        return AppType.NETFLIX

    # Amazon / AWS
    if any(k in s for k in ("amazon", "amazonaws", "cloudfront", "aws")):
        return AppType.AMAZON

    # Microsoft
    if any(k in s for k in ("microsoft", "msn.com", "office", "azure",
                              "live.com", "outlook", "bing")):
        return AppType.MICROSOFT

    # Apple
    if any(k in s for k in ("apple", "icloud", "mzstatic", "itunes")):
        return AppType.APPLE

    # Telegram
    if any(k in s for k in ("telegram", "t.me")):
        return AppType.TELEGRAM

    # TikTok
    if any(k in s for k in ("tiktok", "tiktokcdn", "musical.ly", "bytedance")):
        return AppType.TIKTOK

    # Spotify
    if any(k in s for k in ("spotify", "scdn.co")):
        return AppType.SPOTIFY

    # Zoom
    if "zoom" in s:
        return AppType.ZOOM

    # Discord
    if any(k in s for k in ("discord", "discordapp")):
        return AppType.DISCORD

    # GitHub
    if any(k in s for k in ("github", "githubusercontent")):
        return AppType.GITHUB

    # Cloudflare
    if any(k in s for k in ("cloudflare", "cf-")):
        return AppType.CLOUDFLARE

    # SNI present but unrecognised → generic HTTPS
    return AppType.HTTPS
