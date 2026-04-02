"""
dns.py — DNS leak protection for macOS VPN client.

Redirects all DNS queries through the VPN tunnel by reconfiguring
system DNS settings per network interface using networksetup and scutil.
Saves original configuration and restores it on stop.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
import threading
from dataclasses import dataclass, field
from typing import List, Optional

import structlog

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class InterfaceDNS:
    """Saved DNS settings for one network interface."""

    interface: str
    servers: List[str]  # IPv4/IPv6 addresses; empty list means "empty"
    search_domains: List[str]


@dataclass
class DNSSnapshot:
    """Full DNS snapshot for all active network interfaces."""

    interfaces: List[InterfaceDNS] = field(default_factory=list)
    resolv_conf: Optional[str] = None  # content of /etc/resolv.conf, if readable


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def _run(cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a subprocess command and return the result."""
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Command {cmd} failed (rc={result.returncode}): {result.stderr.strip()}"
        )
    return result


def _get_active_interfaces() -> List[str]:
    """Return all active hardware/Wi-Fi network interfaces via networksetup."""
    result = _run(["networksetup", "-listallnetworkservices"])
    lines = result.stdout.splitlines()
    interfaces: List[str] = []
    for line in lines:
        line = line.strip()
        # Skip header line and asterisk-prefixed (disabled) services
        if not line or line.startswith("*") or "denotes that" in line:
            continue
        interfaces.append(line)
    return interfaces


def _get_interface_dns(interface: str) -> InterfaceDNS:
    """Read current DNS servers for a network service."""
    result = _run(["networksetup", "-getdnsservers", interface], check=False)
    output = result.stdout.strip()

    servers: List[str] = []
    # If DNS is empty/not set, output contains a phrase, not addresses
    if output and not output.lower().startswith("there aren"):
        for line in output.splitlines():
            addr = line.strip()
            if addr:
                try:
                    ipaddress.ip_address(addr)
                    servers.append(addr)
                except ValueError:
                    pass  # Skip non-IP lines

    search_result = _run(
        ["networksetup", "-getsearchdomains", interface], check=False
    )
    search_output = search_result.stdout.strip()
    search_domains: List[str] = []
    if search_output and not search_output.lower().startswith("there aren"):
        for line in search_output.splitlines():
            d = line.strip()
            if d:
                search_domains.append(d)

    return InterfaceDNS(
        interface=interface,
        servers=servers,
        search_domains=search_domains,
    )


def _set_interface_dns(
    interface: str,
    servers: List[str],
    search_domains: Optional[List[str]] = None,
) -> None:
    """Set DNS servers for a network service."""
    if servers:
        _run(["networksetup", "-setdnsservers", interface] + servers)
    else:
        _run(["networksetup", "-setdnsservers", interface, "empty"])

    if search_domains is not None:
        if search_domains:
            _run(
                ["networksetup", "-setsearchdomains", interface] + search_domains
            )
        else:
            _run(["networksetup", "-setsearchdomains", interface, "empty"])


def _read_resolv_conf(path: str = "/etc/resolv.conf") -> Optional[str]:
    """Read /etc/resolv.conf; return None if unreadable."""
    try:
        with open(path, "r") as fh:
            return fh.read()
    except OSError:
        return None


def _write_resolv_conf(content: str, path: str = "/etc/resolv.conf") -> None:
    """Overwrite /etc/resolv.conf (requires root on macOS)."""
    with open(path, "w") as fh:
        fh.write(content)


def _build_resolv_conf(servers: List[str], search_domains: List[str]) -> str:
    """Build resolv.conf content from server list and search domains."""
    lines: List[str] = []
    if search_domains:
        lines.append("search " + " ".join(search_domains))
    for server in servers:
        lines.append(f"nameserver {server}")
    return "\n".join(lines) + "\n"


def _flush_dns_cache() -> None:
    """Flush macOS DNS cache."""
    try:
        _run(["dscacheutil", "-flushcache"], check=False)
        _run(
            ["killall", "-HUP", "mDNSResponder"],
            check=False,
        )
        logger.debug("dns_cache_flushed")
    except Exception as exc:  # noqa: BLE001
        logger.warning("dns_flush_failed", error=str(exc))


# ---------------------------------------------------------------------------
# Snapshot helpers
# ---------------------------------------------------------------------------


def take_snapshot(interfaces: Optional[List[str]] = None) -> DNSSnapshot:
    """Capture DNS configuration for all (or specified) network services."""
    if interfaces is None:
        interfaces = _get_active_interfaces()

    saved: List[InterfaceDNS] = []
    for iface in interfaces:
        try:
            saved.append(_get_interface_dns(iface))
        except Exception as exc:  # noqa: BLE001
            logger.warning("dns_snapshot_iface_error", interface=iface, error=str(exc))

    return DNSSnapshot(
        interfaces=saved,
        resolv_conf=_read_resolv_conf(),
    )


def restore_snapshot(snapshot: DNSSnapshot, *, flush: bool = True) -> None:
    """Restore DNS configuration from a previously taken snapshot."""
    for iface_dns in snapshot.interfaces:
        try:
            _set_interface_dns(
                iface_dns.interface,
                iface_dns.servers,
                iface_dns.search_domains,
            )
            logger.debug(
                "dns_restored",
                interface=iface_dns.interface,
                servers=iface_dns.servers,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "dns_restore_error",
                interface=iface_dns.interface,
                error=str(exc),
            )

    if snapshot.resolv_conf is not None:
        try:
            _write_resolv_conf(snapshot.resolv_conf)
        except OSError as exc:
            logger.warning("resolv_conf_restore_failed", error=str(exc))

    if flush:
        _flush_dns_cache()


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class DNSLeakProtection:
    """Configure system DNS to route all queries through the VPN tunnel.

    Usage::

        protection = DNSLeakProtection(vpn_dns_servers=["10.8.0.1"])
        protection.start()
        # ... VPN is active ...
        protection.stop()

    Or as a context manager::

        with DNSLeakProtection(vpn_dns_servers=["10.8.0.1"]):
            # ... VPN is active ...

    The object is thread-safe: start/stop may be called from any thread.
    """

    def __init__(
        self,
        vpn_dns_servers: List[str],
        *,
        search_domains: Optional[List[str]] = None,
        interfaces: Optional[List[str]] = None,
        update_resolv_conf: bool = True,
    ) -> None:
        """Create a DNSLeakProtection instance.

        Args:
            vpn_dns_servers: List of DNS server IP addresses accessible
                through the VPN tunnel (e.g. ["10.8.0.1"]).
            search_domains: Optional list of search domains to set.
            interfaces: Explicit list of network service names to configure.
                If None, all active services are used.
            update_resolv_conf: Whether to also rewrite /etc/resolv.conf.
        """
        if not vpn_dns_servers:
            raise ValueError("vpn_dns_servers must not be empty")
        for addr in vpn_dns_servers:
            try:
                ipaddress.ip_address(addr)
            except ValueError:
                raise ValueError(f"Invalid DNS server address: {addr!r}")

        self._servers = list(vpn_dns_servers)
        self._search_domains: List[str] = list(search_domains or [])
        self._interfaces = interfaces  # None → discover at start() time
        self._update_resolv_conf = update_resolv_conf

        self._lock = threading.Lock()
        self._snapshot: Optional[DNSSnapshot] = None
        self._active = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def active(self) -> bool:
        """True if DNS leak protection is currently active."""
        with self._lock:
            return self._active

    @property
    def dns_servers(self) -> List[str]:
        """Return the VPN DNS server list."""
        return list(self._servers)

    def start(self) -> None:
        """Activate DNS leak protection.

        Saves current DNS settings and replaces them with VPN DNS servers.
        Raises RuntimeError if already active.
        """
        with self._lock:
            if self._active:
                raise RuntimeError("DNSLeakProtection is already active")

            logger.info("dns_protection_starting", servers=self._servers)

            self._snapshot = take_snapshot(self._interfaces)
            self._apply_vpn_dns()
            self._active = True

            logger.info(
                "dns_protection_active",
                servers=self._servers,
                interfaces=[s.interface for s in self._snapshot.interfaces],
            )

    def stop(self) -> None:
        """Deactivate DNS leak protection and restore original DNS settings.

        Raises RuntimeError if not active.
        """
        with self._lock:
            if not self._active:
                raise RuntimeError("DNSLeakProtection is not active")

            logger.info("dns_protection_stopping")
            if self._snapshot is not None:
                restore_snapshot(self._snapshot)
                self._snapshot = None
            self._active = False
            logger.info("dns_protection_stopped")

    def update_servers(self, new_servers: List[str]) -> None:
        """Update the VPN DNS servers while protection is active.

        Args:
            new_servers: New list of DNS server IP addresses.
        """
        if not new_servers:
            raise ValueError("new_servers must not be empty")
        for addr in new_servers:
            try:
                ipaddress.ip_address(addr)
            except ValueError:
                raise ValueError(f"Invalid DNS server address: {addr!r}")

        with self._lock:
            self._servers = list(new_servers)
            if self._active:
                self._apply_vpn_dns()
                logger.info("dns_servers_updated", servers=self._servers)

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "DNSLeakProtection":
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        if self._active:
            self.stop()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _apply_vpn_dns(self) -> None:
        """Set VPN DNS on all target interfaces (must be called under lock)."""
        interfaces = (
            self._interfaces
            if self._interfaces is not None
            else (
                [s.interface for s in self._snapshot.interfaces]
                if self._snapshot
                else _get_active_interfaces()
            )
        )

        for iface in interfaces:
            try:
                _set_interface_dns(iface, self._servers, self._search_domains or None)
                logger.debug(
                    "dns_set_on_interface",
                    interface=iface,
                    servers=self._servers,
                )
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "dns_set_error", interface=iface, error=str(exc)
                )

        if self._update_resolv_conf:
            try:
                content = _build_resolv_conf(self._servers, self._search_domains)
                _write_resolv_conf(content)
            except OSError as exc:
                logger.warning("resolv_conf_update_failed", error=str(exc))

        _flush_dns_cache()


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------


def dns_protection_for_vpn(
    gateway_ip: str,
    *,
    extra_servers: Optional[List[str]] = None,
    search_domains: Optional[List[str]] = None,
) -> DNSLeakProtection:
    """Create a DNSLeakProtection using the VPN gateway as the DNS server.

    Args:
        gateway_ip: The VPN gateway IP (assigned_ip or gateway from RouteInfo).
        extra_servers: Additional DNS servers to add after the gateway.
        search_domains: Optional DNS search domains.

    Returns:
        A DNSLeakProtection instance (not yet started).
    """
    servers = [gateway_ip] + (extra_servers or [])
    return DNSLeakProtection(
        vpn_dns_servers=servers,
        search_domains=search_domains,
    )
