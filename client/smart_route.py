"""
smart_route.py — Domain-based selective routing for Russia.

Routes traffic to blocked sites through VPN while keeping unblocked sites
direct. This significantly improves performance: ~80-90% of traffic (Yandex,
VK, banks, government sites) bypasses VPN entirely.

Architecture:
  1. Load a blocklist (community-maintained or custom) of blocked domains/IPs.
  2. Resolve domains → IP addresses via system DNS (before VPN changes DNS).
  3. Install specific routes: blocked IPs → VPN tunnel, everything else → direct.
  4. Periodically refresh: re-resolve domains, fetch updated blocklist.

Blocklist sources:
  - AntiZapret community list (https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv)
  - Custom user-supplied file (one domain per line)

Activation:
  - From CLI: ``cavadvpn connect --smart-route``
  - From code: ``SmartRouter(config).start()``

Usage::

    from smart_route import SmartRouter, SmartRouteConfig

    config = SmartRouteConfig(
        vpn_interface="utun5",
        blocklist_urls=["https://example.com/blocked.txt"],
        custom_domains=["youtube.com", "instagram.com"],
    )
    router = SmartRouter(config)
    router.start()

    # Check if a domain is routed via VPN
    router.is_blocked("youtube.com")  # True
    router.is_blocked("yandex.ru")    # False

    # Stats
    router.stats()  # {"blocked_domains": 1234, "blocked_ips": 5678, "direct_domains": ...}

    router.stop()
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set, Tuple
import urllib.request
import urllib.error

import structlog

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Well-known blocklist URLs (community-maintained).
ANTIZAPRET_DOMAINS_URL = (
    "https://raw.githubusercontent.com/zapret-info/z-i/master/nxdomain.txt"
)
# Compact IP list from AntiZapret (already resolved).
ANTIZAPRET_IPS_URL = (
    "https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv"
)

# Default domains that are commonly blocked in Russia.
DEFAULT_BLOCKED_DOMAINS = [
    # Social media
    "instagram.com",
    "www.instagram.com",
    "twitter.com",
    "www.twitter.com",
    "x.com",
    "www.x.com",
    "facebook.com",
    "www.facebook.com",
    # Video
    "youtube.com",
    "www.youtube.com",
    "youtu.be",
    "googlevideo.com",
    "ytimg.com",
    # Messaging
    "discord.com",
    "discord.gg",
    "discordapp.com",
    # Media
    "bbc.com",
    "www.bbc.com",
    "bbc.co.uk",
    # Search & services
    "google.com",
    "www.google.com",
    "gmail.com",
    "linkedin.com",
    "www.linkedin.com",
    # Dev tools
    "medium.com",
    "quora.com",
    "soundcloud.com",
    "twitch.tv",
    "www.twitch.tv",
    # News
    "meduza.io",
    "www.meduza.io",
]

# Domains that should ALWAYS go direct (never through VPN).
# Russian services, banks, government — always accessible, low latency matters.
ALWAYS_DIRECT_DOMAINS = [
    "yandex.ru",
    "ya.ru",
    "mail.ru",
    "vk.com",
    "ok.ru",
    "sberbank.ru",
    "online.sberbank.ru",
    "tinkoff.ru",
    "gosuslugi.ru",
    "mos.ru",
    "nalog.gov.ru",
    "wildberries.ru",
    "ozon.ru",
    "avito.ru",
    "rutube.ru",
]

# How long to cache DNS results (seconds).
_DNS_CACHE_TTL = 600  # 10 minutes
# Max concurrent DNS resolutions.
_DNS_RESOLVE_TIMEOUT = 5.0
# Blocklist refresh interval.
_BLOCKLIST_REFRESH_INTERVAL = 3600  # 1 hour

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


class RouteMode(str, Enum):
    """How the router decides what goes through VPN."""
    BLOCKLIST = "blocklist"  # Only blocked domains → VPN (default, fastest)
    ALLOWLIST = "allowlist"  # Only allowed domains → direct (more secure)


@dataclass
class SmartRouteConfig:
    """Configuration for domain-based smart routing."""

    # VPN tunnel interface name (e.g., "utun5").
    vpn_interface: str = ""

    # Mode: blocklist (blocked → VPN) or allowlist (allowed → direct).
    mode: RouteMode = RouteMode.BLOCKLIST

    # URLs to fetch blocked domain/IP lists from.
    blocklist_urls: List[str] = field(default_factory=list)

    # Path to a local file with blocked domains (one per line).
    blocklist_file: Optional[str] = None

    # Additional domains to always route through VPN.
    custom_domains: List[str] = field(default_factory=list)

    # Include the default hardcoded Russian blocklist.
    use_default_blocklist: bool = True

    # Domains that should always go direct (bypass VPN).
    always_direct: List[str] = field(default_factory=list)

    # DNS server to use for resolving domains (before VPN DNS takes over).
    dns_server: str = ""  # empty = system default

    # How often to refresh the blocklist and re-resolve DNS (seconds).
    refresh_interval: float = _BLOCKLIST_REFRESH_INTERVAL

    # How often to re-resolve DNS for existing domains (seconds).
    dns_ttl: float = _DNS_CACHE_TTL

    # Original gateway (auto-detected if empty).
    original_gateway: str = ""
    original_interface: str = ""


@dataclass
class SmartRouteStats:
    """Statistics for the smart router."""
    blocked_domains: int = 0
    blocked_ips: int = 0
    direct_domains: int = 0
    vpn_routes_installed: int = 0
    dns_resolve_errors: int = 0
    blocklist_last_updated: str = ""
    mode: str = ""


# ---------------------------------------------------------------------------
# DNS resolver
# ---------------------------------------------------------------------------


class _DNSCache:
    """Thread-safe DNS resolution cache with TTL."""

    def __init__(self, ttl: float = _DNS_CACHE_TTL):
        self._ttl = ttl
        self._cache: Dict[str, Tuple[FrozenSet[str], float]] = {}
        self._lock = threading.Lock()
        self._errors = 0

    def resolve(self, domain: str, dns_server: str = "") -> Set[str]:
        """Resolve domain to a set of IPv4 addresses, with caching."""
        with self._lock:
            entry = self._cache.get(domain)
            if entry:
                ips, ts = entry
                if time.monotonic() - ts < self._ttl:
                    return set(ips)

        # Resolve outside the lock.
        ips = self._do_resolve(domain, dns_server)
        with self._lock:
            self._cache[domain] = (frozenset(ips), time.monotonic())
        return ips

    def resolve_many(self, domains: List[str], dns_server: str = "") -> Dict[str, Set[str]]:
        """Resolve multiple domains. Uses threads for parallelism."""
        results: Dict[str, Set[str]] = {}
        to_resolve = []

        # Check cache first.
        with self._lock:
            now = time.monotonic()
            for d in domains:
                entry = self._cache.get(d)
                if entry and now - entry[1] < self._ttl:
                    results[d] = set(entry[0])
                else:
                    to_resolve.append(d)

        if not to_resolve:
            return results

        # Parallel DNS resolution for uncached domains.
        lock = threading.Lock()

        def resolve_one(domain: str):
            ips = self._do_resolve(domain, dns_server)
            with lock:
                results[domain] = ips
            with self._lock:
                self._cache[domain] = (frozenset(ips), time.monotonic())

        threads = []
        # Limit concurrency to avoid DNS flooding.
        batch_size = 50
        for i in range(0, len(to_resolve), batch_size):
            batch = to_resolve[i:i + batch_size]
            batch_threads = []
            for d in batch:
                t = threading.Thread(target=resolve_one, args=(d,), daemon=True)
                t.start()
                batch_threads.append(t)
            for t in batch_threads:
                t.join(timeout=_DNS_RESOLVE_TIMEOUT)
            threads.extend(batch_threads)

        return results

    @property
    def error_count(self) -> int:
        return self._errors

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self._errors = 0

    def _do_resolve(self, domain: str, dns_server: str = "") -> Set[str]:
        """Resolve a domain to IPv4 addresses."""
        ips: Set[str] = set()
        try:
            if dns_server:
                # Use dig with explicit DNS server.
                result = subprocess.run(
                    ["dig", "+short", f"@{dns_server}", domain, "A"],
                    capture_output=True, text=True, timeout=_DNS_RESOLVE_TIMEOUT,
                )
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line and not line.startswith(";"):
                        try:
                            ipaddress.ip_address(line)
                            ips.add(line)
                        except ValueError:
                            pass
            else:
                # System resolver.
                infos = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
                for info in infos:
                    ips.add(info[4][0])
        except (socket.gaierror, socket.timeout, subprocess.TimeoutExpired, OSError):
            self._errors += 1
            logger.debug("smart_route.dns_resolve_failed", domain=domain)
        return ips


# ---------------------------------------------------------------------------
# Blocklist manager
# ---------------------------------------------------------------------------


class _BlocklistManager:
    """Loads and maintains the set of blocked domains and IPs."""

    def __init__(self, config: SmartRouteConfig):
        self._config = config
        self._domains: Set[str] = set()
        self._ips: Set[str] = set()  # Directly specified IPs/CIDRs.
        self._direct_domains: Set[str] = set()
        self._lock = threading.Lock()
        self._last_updated = ""

    def load(self) -> None:
        """Load all blocklist sources."""
        domains: Set[str] = set()
        ips: Set[str] = set()

        # 1. Default hardcoded list.
        if self._config.use_default_blocklist:
            domains.update(DEFAULT_BLOCKED_DOMAINS)

        # 2. Custom domains from config.
        for d in self._config.custom_domains:
            d = d.strip().lower()
            if d:
                domains.add(d)

        # 3. Local file.
        if self._config.blocklist_file:
            file_domains, file_ips = self._load_file(self._config.blocklist_file)
            domains.update(file_domains)
            ips.update(file_ips)

        # 4. Remote URLs.
        for url in self._config.blocklist_urls:
            url_domains, url_ips = self._fetch_url(url)
            domains.update(url_domains)
            ips.update(url_ips)

        # Direct domains.
        direct = set(ALWAYS_DIRECT_DOMAINS)
        for d in self._config.always_direct:
            d = d.strip().lower()
            if d:
                direct.add(d)

        # Remove direct domains from blocked set.
        domains -= direct

        with self._lock:
            self._domains = domains
            self._ips = ips
            self._direct_domains = direct
            self._last_updated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        logger.info(
            "smart_route.blocklist_loaded",
            domains=len(domains),
            ips=len(ips),
            direct=len(direct),
        )

    @property
    def blocked_domains(self) -> Set[str]:
        with self._lock:
            return set(self._domains)

    @property
    def blocked_ips(self) -> Set[str]:
        with self._lock:
            return set(self._ips)

    @property
    def direct_domains(self) -> Set[str]:
        with self._lock:
            return set(self._direct_domains)

    @property
    def last_updated(self) -> str:
        return self._last_updated

    def is_blocked(self, domain: str) -> bool:
        """Check if a domain is in the blocklist."""
        domain = domain.strip().lower()
        with self._lock:
            if domain in self._direct_domains:
                return False
            if domain in self._domains:
                return True
            # Check if it's a subdomain of a blocked domain.
            parts = domain.split(".")
            for i in range(1, len(parts)):
                parent = ".".join(parts[i:])
                if parent in self._domains:
                    return True
            return False

    def add_domain(self, domain: str) -> None:
        """Dynamically add a domain to the blocklist."""
        domain = domain.strip().lower()
        with self._lock:
            self._domains.add(domain)

    def remove_domain(self, domain: str) -> None:
        """Remove a domain from the blocklist."""
        domain = domain.strip().lower()
        with self._lock:
            self._domains.discard(domain)

    @staticmethod
    def _load_file(path: str) -> Tuple[Set[str], Set[str]]:
        """Load domains and IPs from a local file."""
        domains: Set[str] = set()
        ips: Set[str] = set()
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    entry = line.split()[0].lower()
                    if _is_ip_or_cidr(entry):
                        ips.add(entry)
                    elif _DOMAIN_RE.match(entry):
                        domains.add(entry)
        except OSError as e:
            logger.warning("smart_route.blocklist_file_error", path=path, error=str(e))
        return domains, ips

    @staticmethod
    def _fetch_url(url: str) -> Tuple[Set[str], Set[str]]:
        """Fetch a blocklist from a URL."""
        domains: Set[str] = set()
        ips: Set[str] = set()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "CavadVPN/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read().decode("utf-8", errors="replace")
            for line in data.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Handle CSV format (zapret dump.csv: ip;domain;...).
                if ";" in line:
                    parts = line.split(";")
                    for part in parts:
                        part = part.strip()
                        if _is_ip_or_cidr(part):
                            ips.add(part)
                        elif _DOMAIN_RE.match(part):
                            domains.add(part.lower())
                else:
                    entry = line.split()[0].lower()
                    if _is_ip_or_cidr(entry):
                        ips.add(entry)
                    elif _DOMAIN_RE.match(entry):
                        domains.add(entry)
        except (urllib.error.URLError, OSError) as e:
            logger.warning("smart_route.blocklist_url_error", url=url, error=str(e))
        return domains, ips


def _is_ip_or_cidr(s: str) -> bool:
    """Check if a string is an IPv4 address or CIDR."""
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Route installer
# ---------------------------------------------------------------------------


class _RouteInstaller:
    """Installs and removes routes for blocked IPs through the VPN tunnel."""

    def __init__(self, vpn_gateway: str, vpn_interface: str,
                 orig_gateway: str, orig_interface: str):
        self._vpn_gw = vpn_gateway
        self._vpn_if = vpn_interface
        self._orig_gw = orig_gateway
        self._orig_if = orig_interface
        self._vpn_routes: Set[str] = set()  # IPs routed through VPN
        self._lock = threading.Lock()

    def add_vpn_route(self, ip: str) -> bool:
        """Route a specific IP through the VPN tunnel."""
        with self._lock:
            if ip in self._vpn_routes:
                return True
        ok = self._route_cmd("add", ["-host", ip, self._vpn_gw])
        if ok:
            with self._lock:
                self._vpn_routes.add(ip)
        return ok

    def add_vpn_subnet(self, cidr: str) -> bool:
        """Route a subnet through the VPN tunnel."""
        with self._lock:
            if cidr in self._vpn_routes:
                return True
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            ok = self._route_cmd("add", [
                "-net", str(net.network_address),
                "-netmask", str(net.netmask),
                self._vpn_gw,
            ])
        except ValueError:
            return False
        if ok:
            with self._lock:
                self._vpn_routes.add(cidr)
        return ok

    def remove_all(self) -> int:
        """Remove all managed VPN routes. Returns count removed."""
        with self._lock:
            routes = set(self._vpn_routes)
            self._vpn_routes.clear()
        for entry in routes:
            if "/" in entry:
                try:
                    net = ipaddress.ip_network(entry, strict=False)
                    self._route_cmd("delete", [
                        "-net", str(net.network_address),
                        "-netmask", str(net.netmask),
                    ], check=False)
                except ValueError:
                    pass
            else:
                self._route_cmd("delete", ["-host", entry], check=False)
        return len(routes)

    @property
    def route_count(self) -> int:
        with self._lock:
            return len(self._vpn_routes)

    @staticmethod
    def _route_cmd(action: str, args: List[str], check: bool = True) -> bool:
        cmd = ["route", action] + args
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=5.0,
            )
            if result.returncode == 0:
                return True
            if "exists" in result.stderr.lower():
                return True
            if check:
                logger.debug("smart_route.route_cmd_failed",
                             cmd=" ".join(cmd), stderr=result.stderr.strip())
            return False
        except Exception as exc:
            if check:
                logger.debug("smart_route.route_cmd_error",
                             cmd=" ".join(cmd), error=str(exc))
            return False


# ---------------------------------------------------------------------------
# Main SmartRouter class
# ---------------------------------------------------------------------------


class SmartRouter:
    """
    Domain-based selective VPN routing.

    Routes blocked sites through VPN, keeps unblocked sites direct.
    Thread-safe. Activate via ``start()``, deactivate via ``stop()``.
    """

    def __init__(self, config: SmartRouteConfig) -> None:
        self._config = config
        self._blocklist = _BlocklistManager(config)
        self._dns = _DNSCache(ttl=config.dns_ttl)
        self._installer: Optional[_RouteInstaller] = None
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._started = False
        self._lock = threading.Lock()
        # domain → resolved IPs (for route cleanup when domain is removed)
        self._domain_ips: Dict[str, Set[str]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self, vpn_gateway: str = "") -> None:
        """
        Load blocklist, resolve domains, install routes, start background refresh.

        Args:
            vpn_gateway: IP of the VPN gateway (usually the assigned gateway
                         from the control stream).
        """
        if self._started:
            return

        # Detect original gateway before VPN changes the routing table.
        orig_gw = self._config.original_gateway
        orig_if = self._config.original_interface
        if not orig_gw:
            orig_gw, orig_if = _get_default_gateway()

        gw = vpn_gateway or orig_gw
        self._installer = _RouteInstaller(
            vpn_gateway=gw,
            vpn_interface=self._config.vpn_interface,
            orig_gateway=orig_gw,
            orig_interface=orig_if,
        )

        # Load blocklist.
        self._blocklist.load()

        # Initial DNS resolution and route installation.
        self._resolve_and_install()

        # Start background refresh thread.
        self._started = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._refresh_loop, daemon=True, name="smart-route-refresh",
        )
        self._thread.start()
        logger.info("smart_route.started",
                     mode=self._config.mode.value,
                     blocked=len(self._blocklist.blocked_domains),
                     routes=self._installer.route_count)

    def stop(self) -> None:
        """Remove all VPN routes and stop background refresh."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        if self._installer:
            removed = self._installer.remove_all()
            logger.info("smart_route.stopped", routes_removed=removed)
        self._started = False

    def is_blocked(self, domain: str) -> bool:
        """Check if a domain would be routed through VPN."""
        return self._blocklist.is_blocked(domain)

    def add_domain(self, domain: str) -> None:
        """Dynamically add a blocked domain and install routes for it."""
        self._blocklist.add_domain(domain)
        if self._installer:
            ips = self._dns.resolve(domain, self._config.dns_server)
            for ip in ips:
                self._installer.add_vpn_route(ip)
            with self._lock:
                self._domain_ips[domain] = ips

    def remove_domain(self, domain: str) -> None:
        """Remove a domain from the blocklist."""
        self._blocklist.remove_domain(domain)

    def stats(self) -> SmartRouteStats:
        """Return current routing statistics."""
        return SmartRouteStats(
            blocked_domains=len(self._blocklist.blocked_domains),
            blocked_ips=len(self._blocklist.blocked_ips),
            direct_domains=len(self._blocklist.direct_domains),
            vpn_routes_installed=self._installer.route_count if self._installer else 0,
            dns_resolve_errors=self._dns.error_count,
            blocklist_last_updated=self._blocklist.last_updated,
            mode=self._config.mode.value,
        )

    def blocked_domains(self) -> Set[str]:
        """Return the current set of blocked domains."""
        return self._blocklist.blocked_domains

    def direct_domains(self) -> Set[str]:
        """Return the current set of always-direct domains."""
        return self._blocklist.direct_domains

    # Context manager support.
    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _resolve_and_install(self) -> None:
        """Resolve all blocked domains and install VPN routes for their IPs."""
        domains = list(self._blocklist.blocked_domains)
        if not domains and not self._blocklist.blocked_ips:
            return

        # Batch DNS resolution.
        resolved = self._dns.resolve_many(domains, self._config.dns_server)

        # Install routes for resolved IPs.
        if self._installer:
            for domain, ips in resolved.items():
                for ip in ips:
                    self._installer.add_vpn_route(ip)
                with self._lock:
                    self._domain_ips[domain] = ips

            # Install routes for directly specified IPs/CIDRs.
            for ip_or_cidr in self._blocklist.blocked_ips:
                if "/" in ip_or_cidr:
                    self._installer.add_vpn_subnet(ip_or_cidr)
                else:
                    self._installer.add_vpn_route(ip_or_cidr)

    def _refresh_loop(self) -> None:
        """Background thread: periodically refresh blocklist and DNS."""
        while not self._stop_event.wait(self._config.refresh_interval):
            try:
                self._blocklist.load()
                self._dns.clear()
                self._resolve_and_install()
                logger.debug("smart_route.refreshed",
                             routes=self._installer.route_count if self._installer else 0)
            except Exception as e:
                logger.warning("smart_route.refresh_error", error=str(e))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_default_gateway() -> Tuple[str, str]:
    """Return (gateway_ip, interface) from the system routing table."""
    try:
        result = subprocess.run(
            ["netstat", "-rn"], capture_output=True, text=True, timeout=5.0,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 6 and parts[0] in ("default", "0.0.0.0"):
                return parts[1], parts[-1]
    except Exception:
        pass
    return "192.168.1.1", "en0"


# ---------------------------------------------------------------------------
# Factory function
# ---------------------------------------------------------------------------


def create_smart_router(
    vpn_interface: str = "",
    custom_domains: Optional[List[str]] = None,
    blocklist_file: Optional[str] = None,
    blocklist_urls: Optional[List[str]] = None,
    always_direct: Optional[List[str]] = None,
    use_default_blocklist: bool = True,
) -> SmartRouter:
    """
    Create a SmartRouter with sensible defaults.

    Args:
        vpn_interface: TUN interface name (e.g., "utun5").
        custom_domains: Extra domains to route through VPN.
        blocklist_file: Path to local blocklist file.
        blocklist_urls: URLs to fetch blocklists from.
        always_direct: Domains that should never go through VPN.
        use_default_blocklist: Include hardcoded Russian blocklist.
    """
    config = SmartRouteConfig(
        vpn_interface=vpn_interface,
        custom_domains=custom_domains or [],
        blocklist_file=blocklist_file,
        blocklist_urls=blocklist_urls or [],
        always_direct=always_direct or [],
        use_default_blocklist=use_default_blocklist,
    )
    return SmartRouter(config)
