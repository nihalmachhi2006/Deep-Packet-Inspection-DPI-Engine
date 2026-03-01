#!/usr/bin/env python3
"""
tests/test_dpi.py — Unit tests for the Python DPI Engine.
Run with: python -m pytest tests/ -v
       or: python tests/test_dpi.py
"""

import sys
import os
import struct
import unittest
import tempfile

# Make sure the package is importable when run from the project root
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.types import AppType, FiveTuple, ip_to_int, int_to_ip, sni_to_app_type
from src.sni_extractor import SNIExtractor, HTTPHostExtractor, DNSExtractor
from src.rule_manager import RuleManager


# ──────────────────────────────────────────────────────────────────────────────
# Helpers — build minimal TLS Client Hello bytes
# ──────────────────────────────────────────────────────────────────────────────

def _tls_client_hello(sni: str) -> bytes:
    sni_bytes = sni.encode()
    sni_ext_data = (
        struct.pack("!H", len(sni_bytes) + 3) +
        b"\x00" +
        struct.pack("!H", len(sni_bytes)) +
        sni_bytes
    )
    sni_ext = struct.pack("!HH", 0x0000, len(sni_ext_data)) + sni_ext_data
    ext_block = struct.pack("!H", len(sni_ext)) + sni_ext

    body = (
        b"\x03\x03"
        + b"\x00" * 32
        + b"\x00"
        + struct.pack("!H", 2) + b"\xc0\x2b"
        + b"\x01\x00"
        + ext_block
    )

    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


# ──────────────────────────────────────────────────────────────────────────────
# Test cases
# ──────────────────────────────────────────────────────────────────────────────

class TestTypes(unittest.TestCase):

    def test_ip_roundtrip(self):
        ip = "192.168.1.100"
        self.assertEqual(int_to_ip(ip_to_int(ip)), ip)

    def test_ip_to_int(self):
        # 192 = first octet → shift 0; .168 → shift 8; .1 → shift 16; .1 → shift 24
        val = ip_to_int("1.0.0.0")
        self.assertEqual(val & 0xFF, 1)

    def test_five_tuple_hash(self):
        t1 = FiveTuple(1, 2, 80, 443, 6)
        t2 = FiveTuple(1, 2, 80, 443, 6)
        self.assertEqual(hash(t1), hash(t2))
        d = {t1: "value"}
        self.assertEqual(d[t2], "value")

    def test_sni_to_app_type(self):
        self.assertEqual(sni_to_app_type("www.youtube.com"),  AppType.YOUTUBE)
        self.assertEqual(sni_to_app_type("www.facebook.com"), AppType.FACEBOOK)
        self.assertEqual(sni_to_app_type("github.com"),       AppType.GITHUB)
        self.assertEqual(sni_to_app_type("discord.com"),      AppType.DISCORD)
        self.assertEqual(sni_to_app_type("open.spotify.com"), AppType.SPOTIFY)
        self.assertEqual(sni_to_app_type("zoom.us"),          AppType.ZOOM)
        self.assertEqual(sni_to_app_type("unknown.example"),  AppType.HTTPS)
        self.assertEqual(sni_to_app_type(""),                 AppType.UNKNOWN)


class TestSNIExtractor(unittest.TestCase):

    def test_extract_sni(self):
        for domain in ("www.youtube.com", "github.com", "example.com"):
            payload = _tls_client_hello(domain)
            result = SNIExtractor.extract(payload)
            self.assertEqual(result, domain, f"Failed for domain: {domain}")

    def test_not_tls(self):
        self.assertIsNone(SNIExtractor.extract(b"GET / HTTP/1.1\r\n"))

    def test_too_short(self):
        self.assertIsNone(SNIExtractor.extract(b"\x16\x03\x01"))

    def test_is_client_hello(self):
        payload = _tls_client_hello("example.com")
        self.assertTrue(SNIExtractor.is_client_hello(payload))
        self.assertFalse(SNIExtractor.is_client_hello(b"\x17\x03\x01\x00\x05hello"))


class TestHTTPHostExtractor(unittest.TestCase):

    def test_extract_host(self):
        req = b"GET / HTTP/1.1\r\nHost: www.example.com\r\nAccept: */*\r\n\r\n"
        self.assertEqual(HTTPHostExtractor.extract(req), "www.example.com")

    def test_host_with_port(self):
        req = b"GET / HTTP/1.1\r\nHost: www.example.com:8080\r\n\r\n"
        self.assertEqual(HTTPHostExtractor.extract(req), "www.example.com")

    def test_not_http(self):
        self.assertIsNone(HTTPHostExtractor.extract(b"\x16\x03\x01\x00\x05hello"))

    def test_no_host_header(self):
        req = b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n"
        self.assertIsNone(HTTPHostExtractor.extract(req))


class TestDNSExtractor(unittest.TestCase):

    def _dns_query(self, domain: str) -> bytes:
        qname = b""
        for label in domain.split("."):
            lb = label.encode()
            qname += bytes([len(lb)]) + lb
        qname += b"\x00"
        return struct.pack("!HHHHHH", 1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)

    def test_extract_domain(self):
        payload = self._dns_query("www.example.com")
        self.assertEqual(DNSExtractor.extract(payload), "www.example.com")

    def test_dns_response_ignored(self):
        payload = self._dns_query("example.com")
        # Flip QR bit to mark as response
        flags_bytes = bytearray(payload)
        flags_bytes[2] |= 0x80
        self.assertIsNone(DNSExtractor.extract(bytes(flags_bytes)))


class TestRuleManager(unittest.TestCase):

    def setUp(self):
        self.rules = RuleManager()

    def test_block_ip(self):
        self.rules.block_ip("192.168.1.50")
        self.assertTrue(self.rules.is_blocked(ip_to_int("192.168.1.50"), AppType.UNKNOWN, ""))
        self.assertFalse(self.rules.is_blocked(ip_to_int("192.168.1.51"), AppType.UNKNOWN, ""))

    def test_block_app(self):
        self.rules.block_app("YouTube")
        self.assertTrue(self.rules.is_blocked(0, AppType.YOUTUBE, ""))
        self.assertFalse(self.rules.is_blocked(0, AppType.GITHUB, ""))

    def test_block_domain(self):
        self.rules.block_domain("tiktok")
        self.assertTrue(self.rules.is_blocked(0, AppType.UNKNOWN, "www.tiktok.com"))
        self.assertFalse(self.rules.is_blocked(0, AppType.UNKNOWN, "www.youtube.com"))

    def test_no_rules(self):
        self.assertFalse(self.rules.has_rules)
        self.assertFalse(self.rules.is_blocked(0, AppType.YOUTUBE, "www.youtube.com"))

    def test_has_rules(self):
        self.rules.block_app("Discord")
        self.assertTrue(self.rules.has_rules)


class TestIntegration(unittest.TestCase):
    """End-to-end test using generated PCAP."""

    def test_single_threaded_pipeline(self):
        import subprocess

        # Use abspath so this works on Windows regardless of how pytest is invoked
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        gen_script   = os.path.join(project_root, "generate_test_pcap.py")

        with tempfile.TemporaryDirectory() as tmpdir:
            pcap_in  = os.path.join(tmpdir, "test.pcap")
            pcap_out = os.path.join(tmpdir, "out.pcap")

            # Generate test PCAP
            result = subprocess.run(
                [sys.executable, gen_script, pcap_in],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                self.fail(
                    f"generate_test_pcap.py failed:\n"
                    f"STDOUT: {result.stdout}\n"
                    f"STDERR: {result.stderr}"
                )

            # Run DPI engine
            from src.rule_manager import RuleManager
            from src.dpi_engine import DPIEngine
            rules = RuleManager()
            rules.block_app("YouTube")
            engine = DPIEngine(rules)
            engine.process(pcap_in, pcap_out)

            # Output file should exist and be smaller than input (YouTube dropped)
            self.assertTrue(os.path.exists(pcap_out))
            self.assertGreater(os.path.getsize(pcap_in), 0)
            self.assertGreater(os.path.getsize(pcap_out), 0)
            self.assertLess(os.path.getsize(pcap_out), os.path.getsize(pcap_in))


if __name__ == "__main__":
    unittest.main(verbosity=2)
