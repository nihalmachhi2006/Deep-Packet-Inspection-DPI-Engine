"""
sni_extractor.py - Extract domain names from TLS Client Hello, HTTP Host headers,
and DNS queries.
Mirrors sni_extractor.h / sni_extractor.cpp from the original C++ project.
Pure stdlib.
"""

from __future__ import annotations
import struct
from typing import Optional

# TLS constants
TLS_CONTENT_HANDSHAKE  = 0x16
TLS_HANDSHAKE_CLIENT_HELLO = 0x01
TLS_EXTENSION_SNI      = 0x0000
TLS_SNI_TYPE_HOSTNAME  = 0x00

TLS_VERSION_MIN = 0x0300  # SSL 3.0
TLS_VERSION_MAX = 0x0304  # TLS 1.3


class SNIExtractor:
    """Extract the Server Name Indication from a TLS Client Hello payload."""

    @staticmethod
    def _read_u16be(data: bytes, offset: int) -> int:
        return struct.unpack_from("!H", data, offset)[0]

    @staticmethod
    def _read_u24be(data: bytes, offset: int) -> int:
        return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]

    @classmethod
    def is_client_hello(cls, payload: bytes) -> bool:
        if len(payload) < 9:
            return False
        if payload[0] != TLS_CONTENT_HANDSHAKE:
            return False
        version = cls._read_u16be(payload, 1)
        if not (TLS_VERSION_MIN <= version <= TLS_VERSION_MAX):
            return False
        record_len = cls._read_u16be(payload, 3)
        if record_len > len(payload) - 5:
            return False
        if payload[5] != TLS_HANDSHAKE_CLIENT_HELLO:
            return False
        return True

    @classmethod
    def extract(cls, payload: bytes) -> Optional[str]:
        """Return the SNI hostname, or None if not found."""
        if not cls.is_client_hello(payload):
            return None

        offset = 5  # skip TLS record header

        # Handshake header: type(1) + length(3)
        # _handshake_len = cls._read_u24be(payload, offset + 1)
        offset += 4

        # Client Hello body
        offset += 2   # client_version
        offset += 32  # random

        if offset >= len(payload):
            return None

        # Session ID
        session_id_len = payload[offset]
        offset += 1 + session_id_len

        if offset + 2 > len(payload):
            return None

        # Cipher suites
        cipher_suites_len = cls._read_u16be(payload, offset)
        offset += 2 + cipher_suites_len

        if offset >= len(payload):
            return None

        # Compression methods
        comp_methods_len = payload[offset]
        offset += 1 + comp_methods_len

        if offset + 2 > len(payload):
            return None

        # Extensions
        ext_total_len = cls._read_u16be(payload, offset)
        offset += 2
        ext_end = min(offset + ext_total_len, len(payload))

        while offset + 4 <= ext_end:
            ext_type = cls._read_u16be(payload, offset)
            ext_len  = cls._read_u16be(payload, offset + 2)
            offset  += 4

            if offset + ext_len > ext_end:
                break

            if ext_type == TLS_EXTENSION_SNI:
                # SNI extension structure:
                #   SNI list length  (2)
                #   SNI type         (1) → 0x00 for hostname
                #   SNI name length  (2)
                #   SNI name         (variable)
                if ext_len < 5:
                    break
                # sni_list_len = cls._read_u16be(payload, offset)
                sni_type = payload[offset + 2]
                sni_name_len = cls._read_u16be(payload, offset + 3)
                if sni_type != TLS_SNI_TYPE_HOSTNAME:
                    break
                if sni_name_len > ext_len - 5:
                    break
                return payload[offset + 5: offset + 5 + sni_name_len].decode("utf-8", errors="ignore")

            offset += ext_len

        return None


class HTTPHostExtractor:
    """Extract the Host header from an HTTP/1.x request payload."""

    _HTTP_METHODS = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI")

    @classmethod
    def is_http_request(cls, payload: bytes) -> bool:
        if len(payload) < 4:
            return False
        return any(payload[:4] == m for m in cls._HTTP_METHODS)

    @classmethod
    def extract(cls, payload: bytes) -> Optional[str]:
        """Return the Host header value (without port), or None."""
        if not cls.is_http_request(payload):
            return None

        # Search for "Host:" (case-insensitive)
        lower = payload.lower()
        idx = lower.find(b"host:")
        if idx == -1:
            return None

        start = idx + 5
        # Skip leading whitespace
        while start < len(payload) and payload[start] in (ord(" "), ord("\t")):
            start += 1

        # Read until newline
        end = start
        while end < len(payload) and payload[end] not in (ord("\r"), ord("\n")):
            end += 1

        if end <= start:
            return None

        host = payload[start:end].decode("utf-8", errors="ignore").strip()
        # Strip port number if present
        if ":" in host:
            host = host.split(":")[0]
        return host or None


class DNSExtractor:
    """Extract the queried domain name from a DNS query payload."""

    @staticmethod
    def is_dns_query(payload: bytes) -> bool:
        if len(payload) < 12:
            return False
        # QR bit (byte 2, bit 7): 0 = query
        if payload[2] & 0x80:
            return False
        qdcount = struct.unpack_from("!H", payload, 4)[0]
        return qdcount > 0

    @classmethod
    def extract(cls, payload: bytes) -> Optional[str]:
        if not cls.is_dns_query(payload):
            return None

        offset = 12
        labels = []
        while offset < len(payload):
            label_len = payload[offset]
            if label_len == 0:
                break
            if label_len > 63:
                break  # Compression pointer — not supported in this simple parser
            offset += 1
            if offset + label_len > len(payload):
                break
            labels.append(payload[offset: offset + label_len].decode("utf-8", errors="ignore"))
            offset += label_len

        return ".".join(labels) if labels else None
