from __future__ import annotations
import struct
from typing import Optional

TLS_CONTENT_HANDSHAKE  = 0x16
TLS_HANDSHAKE_CLIENT_HELLO = 0x01
TLS_EXTENSION_SNI      = 0x0000
TLS_SNI_TYPE_HOSTNAME  = 0x00

TLS_VERSION_MIN = 0x0300
TLS_VERSION_MAX = 0x0304


class SNIExtractor:
    @staticmethod
    def _read_u16be(data: bytes, offset: int) -> int:
        return struct.unpack_from("!H", data, offset)[0]

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
        if not cls.is_client_hello(payload):
            return None

        offset = 5
        offset += 4

        offset += 2
        offset += 32

        if offset >= len(payload):
            return None

        session_id_len = payload[offset]
        offset += 1 + session_id_len

        if offset + 2 > len(payload):
            return None

        cipher_suites_len = cls._read_u16be(payload, offset)
        offset += 2 + cipher_suites_len

        if offset >= len(payload):
            return None

        comp_methods_len = payload[offset]
        offset += 1 + comp_methods_len

        if offset + 2 > len(payload):
            return None

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
                if ext_len < 5:
                    break
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
    _HTTP_METHODS = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI")

    @classmethod
    def is_http_request(cls, payload: bytes) -> bool:
        if len(payload) < 4:
            return False
        return any(payload[:4] == m for m in cls._HTTP_METHODS)

    @classmethod
    def extract(cls, payload: bytes) -> Optional[str]:
        if not cls.is_http_request(payload):
            return None

        lower = payload.lower()
        idx = lower.find(b"host:")
        if idx == -1:
            return None

        start = idx + 5
        while start < len(payload) and payload[start] in (ord(" "), ord("\t")):
            start += 1

        end = start
        while end < len(payload) and payload[end] not in (ord("\r"), ord("\n")):
            end += 1

        if end <= start:
            return None

        host = payload[start:end].decode("utf-8", errors="ignore").strip()
        if ":" in host:
            host = host.split(":")[0]
        return host or None


class DNSExtractor:
    @staticmethod
    def is_dns_query(payload: bytes) -> bool:
        if len(payload) < 12:
            return False
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
                break
            offset += 1
            if offset + label_len > len(payload):
                break
            labels.append(payload[offset: offset + label_len].decode("utf-8", errors="ignore"))
            offset += label_len

        return ".".join(labels) if labels else None
