from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse

from .deadline import ScanDeadline


_HTTP_SCHEMES = {"http", "https"}


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str = ""


class ScopePolicy:
    """Single source of truth for outbound HTTP(S) scope enforcement.

    The policy validates URL syntax, domain allowlists, excluded paths and
    literal/resolved IP addresses. Private, loopback, link-local, multicast,
    unspecified and reserved addresses are denied unless ``scope.allow_private``
    is explicitly enabled. It also observes the process-wide scan deadline so
    discovery/browser/request layers stop creating new outbound work after the
    configured wall-clock budget expires.
    """

    def __init__(self, config: dict):
        self.config = config
        scope = config.get("scope", {})
        self.include_domains = [
            str(item).strip()
            for item in scope.get("include_domains", [])
            if str(item).strip()
        ]
        self.exclude_paths = [
            str(item) for item in scope.get("exclude_paths", []) if str(item)
        ]
        self.allow_private = bool(scope.get("allow_private", False))
        self.resolve_dns = bool(scope.get("resolve_dns", True))
        self.max_url_length = int(
            config.get("crawler", {}).get("max_url_length", 2048)
        )
        self.deadline = ScanDeadline.from_config(config)

        target = str(config.get("target", "") or "")
        target_parsed = urlparse(target)
        self.target_host = self._normalize_host(target_parsed.hostname or "")
        self.target_netloc = (target_parsed.netloc or "").lower().rstrip(".")

    @staticmethod
    def _normalize_host(host: str) -> str:
        return (host or "").strip().lower().rstrip(".")

    @staticmethod
    def _is_sensitive_ip(value: str) -> bool:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return False
        return any(
            (
                ip.is_private,
                ip.is_loopback,
                ip.is_link_local,
                ip.is_multicast,
                ip.is_unspecified,
                ip.is_reserved,
            )
        )

    @staticmethod
    def _split_domain_pattern(pattern: str) -> tuple[str, str | None]:
        pattern = pattern.strip().lower().rstrip(".")
        if pattern.startswith("["):
            closing = pattern.find("]")
            if closing != -1:
                host = pattern[1:closing]
                port = (
                    pattern[closing + 2 :]
                    if pattern[closing + 1 : closing + 2] == ":"
                    else None
                )
                return host, port
        if pattern.count(":") == 1:
            host, port = pattern.rsplit(":", 1)
            if port.isdigit():
                return host, port
        return pattern, None

    def _domain_allowed(self, host: str, port: int | None, netloc: str) -> bool:
        host = self._normalize_host(host)
        netloc = (netloc or host).lower().rstrip(".")

        patterns = list(self.include_domains)
        if not patterns and self.target_host:
            patterns = [self.target_netloc or self.target_host]
        # Preserve RequestManager's library-level behavior when callers build a
        # manager without a target/allowlist. The CLI always pins the target
        # into include_domains before RequestManager is created.
        if not patterns:
            return True

        for raw_pattern in patterns:
            wildcard = raw_pattern.startswith("*.")
            pattern = raw_pattern[2:] if wildcard else raw_pattern
            pattern_host, pattern_port = self._split_domain_pattern(pattern)
            pattern_host = self._normalize_host(pattern_host)

            if pattern_port is not None and str(port or "") != pattern_port:
                continue

            if wildcard:
                if host == pattern_host or host.endswith(f".{pattern_host}"):
                    return True
                continue

            if host == pattern_host:
                return True
            if (
                pattern_port is not None
                and netloc == raw_pattern.lower().rstrip(".")
            ):
                return True
        return False

    @staticmethod
    def _resolved_addresses(host: str) -> Iterable[str]:
        seen: set[str] = set()
        for family, _socktype, _proto, _canonname, sockaddr in socket.getaddrinfo(
            host, None
        ):
            if family == socket.AF_INET:
                address = sockaddr[0]
            elif family == socket.AF_INET6:
                address = sockaddr[0]
            else:
                continue
            if address not in seen:
                seen.add(address)
                yield address

    def evaluate(
        self, url: str, *, resolve_dns: bool | None = None
    ) -> ScopeDecision:
        if self.deadline.expired():
            return ScopeDecision(False, "global scan deadline exceeded")
        if not isinstance(url, str) or not url:
            return ScopeDecision(False, "empty URL")
        if len(url) > self.max_url_length:
            return ScopeDecision(False, "URL exceeds configured maximum length")

        parsed = urlparse(url)
        if parsed.scheme.lower() not in _HTTP_SCHEMES:
            return ScopeDecision(
                False, f"unsupported URL scheme: {parsed.scheme or '<missing>'}"
            )
        if parsed.username is not None or parsed.password is not None:
            return ScopeDecision(False, "userinfo in URL is not allowed")

        host = self._normalize_host(parsed.hostname or "")
        if not host:
            return ScopeDecision(False, "URL has no hostname")
        if any(parsed.path.startswith(prefix) for prefix in self.exclude_paths):
            return ScopeDecision(False, "path excluded by scope policy")
        if not self._domain_allowed(host, parsed.port, parsed.netloc):
            return ScopeDecision(
                False,
                f"host {parsed.netloc or host} is outside configured scope",
            )

        if self._is_sensitive_ip(host) and not self.allow_private:
            return ScopeDecision(
                False, f"sensitive IP address {host} is not allowed"
            )

        should_resolve = (
            self.resolve_dns if resolve_dns is None else bool(resolve_dns)
        )
        if should_resolve and not self.allow_private and not self._is_sensitive_ip(host):
            try:
                resolved = list(self._resolved_addresses(host))
            except socket.gaierror as exc:
                return ScopeDecision(
                    False, f"DNS resolution failed for {host}: {exc}"
                )
            if not resolved:
                return ScopeDecision(
                    False, f"DNS resolution returned no addresses for {host}"
                )
            sensitive = [
                address for address in resolved if self._is_sensitive_ip(address)
            ]
            if sensitive:
                return ScopeDecision(
                    False, f"hostname {host} resolves to a non-public address"
                )

        return ScopeDecision(True, "allowed")

    def is_allowed(self, url: str, *, resolve_dns: bool | None = None) -> bool:
        return self.evaluate(url, resolve_dns=resolve_dns).allowed

    def require(self, url: str, *, resolve_dns: bool | None = None) -> None:
        decision = self.evaluate(url, resolve_dns=resolve_dns)
        if not decision.allowed:
            if decision.reason == "global scan deadline exceeded":
                raise TimeoutError("Global scan deadline exceeded")
            raise RuntimeError(f"URL blocked by scope policy: {decision.reason}")
