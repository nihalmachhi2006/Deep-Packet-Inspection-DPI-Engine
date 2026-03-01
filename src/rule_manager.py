"""
rule_manager.py - Manage blocking rules (IP, application, domain).
Mirrors rule_manager.h / rule_manager.cpp from the original C++ project.
"""

from __future__ import annotations
from typing import Set, List
from .types import AppType, ip_to_int


class RuleManager:
    """
    Stores and evaluates blocking rules.

    Rule types:
        - IP        : block all traffic from a source IP
        - App       : block all traffic classified as a given AppType
        - Domain    : substring match against the SNI / HTTP Host
    """

    def __init__(self) -> None:
        self._blocked_ips:     Set[int]     = set()
        self._blocked_apps:    Set[AppType] = set()
        self._blocked_domains: List[str]    = []

    # ── Rule registration ────────────────────────────────────────────────────

    def block_ip(self, ip: str) -> None:
        addr = ip_to_int(ip)
        self._blocked_ips.add(addr)
        print(f"[Rules] Blocked IP: {ip}")

    def block_app(self, app_name: str) -> None:
        for app in AppType:
            if app.value.lower() == app_name.lower():
                self._blocked_apps.add(app)
                print(f"[Rules] Blocked app: {app.value}")
                return
        print(f"[Rules] WARNING: Unknown app '{app_name}'")

    def block_domain(self, domain: str) -> None:
        self._blocked_domains.append(domain.lower())
        print(f"[Rules] Blocked domain pattern: {domain}")

    # ── Evaluation ───────────────────────────────────────────────────────────

    def is_blocked(self, src_ip_int: int, app_type: AppType, sni: str) -> bool:
        """Return True if any rule matches this packet/flow."""
        if src_ip_int in self._blocked_ips:
            return True
        if app_type in self._blocked_apps:
            return True
        sni_lower = sni.lower()
        for pattern in self._blocked_domains:
            if pattern in sni_lower:
                return True
        return False

    @property
    def has_rules(self) -> bool:
        return bool(self._blocked_ips or self._blocked_apps or self._blocked_domains)
