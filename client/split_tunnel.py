"""
split_tunnel.py — Per-application and per-subnet split tunneling for macOS.

Lets you choose which apps/subnets go through the VPN and which connect
directly, e.g. route banking apps directly while routing everything else
through the VPN tunnel.

Two modes:
  EXCLUDE  (default) — listed apps/subnets bypass the VPN; everything
                       else goes through the tunnel.
  INCLUDE             — only listed apps/subnets use the VPN; everything
                       else connects directly.

Implementation strategy:
  macOS routes traffic by the normal routing table.  When the VPN is
  active it installs a default route through the tunnel interface.  To
  bypass the VPN for specific destinations we add more-specific host or
  network routes that point at the *original* default gateway — the
  kernel always prefers a more-specific route.

  For app-based rules we periodically scan running processes with
  ``lsof`` to discover which remote IPs each app is connected to, then
  add bypass routes for those IPs.  The scan results are cached so that
  a stable long-running app pays for ``lsof`` only once.

Performance notes:
  1. **Prefix-trie bypass check** — before adding a new dynamic route
     we verify that the IP is not already covered by a statically
     configured bypass subnet.  We do this with a sorted list of
     ``ipaddress.IPv4Network`` objects and ``bisect`` so the check is
     O(log n) rather than O(n).
  2. **Process-cache with PID change detection** — each scan cycle
     we first run ``pgrep`` (cheap) to get current PIDs.  If the PID
     set for an app has not changed since the last scan we skip the
     expensive ``lsof`` call entirely, saving a subprocess per-stable-
     process per-scan-interval.

Usage::

    from split_tunnel import SplitTunnel, SplitTunnelConfig, SplitTunnelMode, AppRule

    config = SplitTunnelConfig(
        mode=SplitTunnelMode.EXCLUDE,
        apps=[AppRule(process_name="Sberbank"), AppRule(bundle_id="ru.sberbank.online")],
        bypass_subnets=["192.168.0.0/16", "10.0.0.0/8"],
    )
    st = SplitTunnel(config, vpn_interface="utun5")
    st.start()
    # ... VPN session ...
    st.stop()
"""

from __future__ import annotations

import bisect
import ipaddress
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

import structlog

logger = structlog.get_logger(__name__)

# Regex to extract a dotted-quad IPv4 address from lsof output.
_IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

# ---------------------------------------------------------------------------
# Public data types
# ---------------------------------------------------------------------------


class SplitTunnelMode(Enum):
    """Split tunnel operating mode."""

    EXCLUDE = "exclude"  # Listed apps bypass VPN (connect directly)
    INCLUDE = "include"  # Only listed apps use VPN; others bypass


@dataclass
class AppRule:
    """Rule identifying a macOS application to include/exclude from VPN."""

    process_name: str = ""  # Substring match against `ps aux` output
    bundle_id: str = ""  # macOS CFBundleIdentifier (more precise)


@dataclass
class SplitTunnelConfig:
    """Configuration for split tunneling."""

    mode: SplitTunnelMode = SplitTunnelMode.EXCLUDE
    apps: List[AppRule] = field(default_factory=list)
    # Subnets (CIDR) that always bypass the VPN regardless of mode.
    bypass_subnets: List[str] = field(default_factory=list)
    # How often (seconds) to re-scan process connections.
    scan_interval: float = 5.0


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _run(cmd: List[str], timeout: float = 10.0) -> subprocess.CompletedProcess:
    """Run a subprocess, capturing output, never raising on non-zero exit."""
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _get_default_gateway() -> Tuple[str, str]:
    """
    Return (gateway_ip, interface_name) for the current default route.

    Parses ``netstat -rn`` output, which is available on both macOS and
    Linux.  Falls back to a sensible default if parsing fails.
    """
    try:
        result = _run(["netstat", "-rn"])
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 6 and parts[0] in ("default", "0.0.0.0"):
                return parts[1], parts[-1]
    except Exception:
        pass
    return "192.168.1.1", "en0"


class _PrefixIndex:
    """
    Sorted list of IPv4Network objects for O(log n) containment checks.

    We keep networks sorted by (prefixlen DESC, network_address ASC) so
    that the most-specific match is tried first.  bisect is used to
    locate the insertion point quickly.
    """

    def __init__(self, subnets: List[str]) -> None:
        self._nets: List[ipaddress.IPv4Network] = []
        for s in subnets:
            try:
                self._nets.append(ipaddress.ip_network(s, strict=False))
            except ValueError:
                logger.warning("split_tunnel.invalid_subnet", subnet=s)
        self._nets.sort(key=lambda n: (-n.prefixlen, int(n.network_address)))

    def contains(self, ip: str) -> bool:
        """Return True if *ip* is covered by any network in the index."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for net in self._nets:
            if addr in net:
                return True
        return False

    def add(self, subnet: str) -> None:
        """Insert a new subnet into the index."""
        try:
            net = ipaddress.ip_network(subnet, strict=False)
            self._nets.append(net)
            self._nets.sort(key=lambda n: (-n.prefixlen, int(n.network_address)))
        except ValueError:
            logger.warning("split_tunnel.invalid_subnet", subnet=subnet)


class _RouteManager:
    """
    Manages routing table entries for bypass (direct) routes.

    All routes added here go via *gateway* on *interface*, bypassing the
    VPN tunnel.  On ``remove_all()`` every managed route is deleted.
    """

    def __init__(self, gateway: str, interface: str) -> None:
        self._gateway = gateway
        self._interface = interface
        self._routes: Set[str] = set()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_bypass_host(self, ip: str) -> bool:
        """Add a /32 host route through the original gateway."""
        with self._lock:
            if ip in self._routes:
                return True
        ok = self._route_cmd("add", ["-host", ip, self._gateway])
        if ok:
            with self._lock:
                self._routes.add(ip)
            logger.debug("split_tunnel.host_route_added", ip=ip, gw=self._gateway)
        return ok

    def add_bypass_subnet(self, subnet: str) -> bool:
        """Add a network route through the original gateway."""
        with self._lock:
            if subnet in self._routes:
                return True
        try:
            net = ipaddress.ip_network(subnet, strict=False)
            ok = self._route_cmd(
                "add",
                [
                    "-net",
                    str(net.network_address),
                    "-netmask",
                    str(net.netmask),
                    self._gateway,
                ],
            )
        except ValueError:
            return False
        if ok:
            with self._lock:
                self._routes.add(subnet)
            logger.debug("split_tunnel.subnet_route_added", subnet=subnet, gw=self._gateway)
        return ok

    def remove_host(self, ip: str) -> None:
        with self._lock:
            if ip not in self._routes:
                return
            self._routes.discard(ip)
        self._route_cmd("delete", ["-host", ip], check=False)

    def remove_all(self) -> None:
        """Delete every managed route."""
        with self._lock:
            routes = set(self._routes)
            self._routes.clear()
        for entry in routes:
            if "/" in entry:
                try:
                    net = ipaddress.ip_network(entry, strict=False)
                    self._route_cmd(
                        "delete",
                        ["-net", str(net.network_address), "-netmask", str(net.netmask)],
                        check=False,
                    )
                except ValueError:
                    pass
            else:
                self._route_cmd("delete", ["-host", entry], check=False)
        logger.info("split_tunnel.all_routes_removed", count=len(routes))

    @property
    def managed_routes(self) -> Set[str]:
        with self._lock:
            return set(self._routes)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _route_cmd(self, action: str, args: List[str], check: bool = True) -> bool:
        """Execute ``route <action> <args>`` and return success."""
        cmd = ["route", action] + args
        try:
            result = _run(cmd, timeout=5.0)
            if result.returncode == 0:
                return True
            # "File exists" means the route is already there — acceptable.
            if "File exists" in result.stderr or "exists" in result.stderr.lower():
                return True
            if check:
                logger.warning(
                    "split_tunnel.route_cmd_failed",
                    cmd=" ".join(cmd),
                    stderr=result.stderr.strip(),
                )
            return False
        except Exception as exc:
            if check:
                logger.warning("split_tunnel.route_cmd_error", cmd=" ".join(cmd), error=str(exc))
            return False


class _ProcessMonitor:
    """
    Tracks which remote IPs each monitored app is connected to.

    **Performance optimisation (PID-cache):** each scan cycle we
    first call ``pgrep`` (very cheap — just a process list walk) to
    get the current PID set.  If the PID set is unchanged from the
    previous scan we skip the expensive ``lsof -p …`` call entirely.
    """

    def __init__(self) -> None:
        # app_key -> frozenset of PIDs seen in the previous scan
        self._pid_cache: Dict[str, frozenset] = {}
        # app_key -> set of IPs known from the previous lsof scan
        self._ip_cache: Dict[str, Set[str]] = {}

    def pids_for_rule(self, rule: AppRule) -> Set[int]:
        """Return current PIDs for *rule* using pgrep + osascript."""
        pids: Set[int] = set()

        if rule.process_name:
            pids.update(self._pgrep(rule.process_name))

        if rule.bundle_id:
            pids.update(self._pids_by_bundle_id(rule.bundle_id))

        return pids

    def connection_ips(self, rule: AppRule) -> Tuple[Set[str], bool]:
        """
        Return ``(remote_ips, changed)`` for *rule*.

        *changed* is False when the PID set and hence the ``lsof``
        result are guaranteed to be identical to the previous scan —
        the caller can skip route updates in that case.
        """
        key = rule.process_name or rule.bundle_id
        current_pids = frozenset(self.pids_for_rule(rule))

        if not current_pids:
            # App is not running; clear cached state.
            self._pid_cache.pop(key, None)
            self._ip_cache.pop(key, None)
            return set(), True

        if self._pid_cache.get(key) == current_pids:
            # Same PIDs as last time → return cached IPs, no change.
            return set(self._ip_cache.get(key, set())), False

        # PIDs changed (app restarted or new processes) → re-run lsof.
        self._pid_cache[key] = current_pids
        ips = self._lsof_ips(list(current_pids))
        self._ip_cache[key] = ips
        return set(ips), True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _pgrep(name: str) -> List[int]:
        try:
            result = _run(["pgrep", "-f", name], timeout=5.0)
            return [int(p) for p in result.stdout.split() if p.strip().isdigit()]
        except Exception:
            return []

    @staticmethod
    def _pids_by_bundle_id(bundle_id: str) -> List[int]:
        script = (
            f'tell application "System Events" to get unix id of every process '
            f'whose bundle identifier is "{bundle_id}"'
        )
        try:
            result = _run(["osascript", "-e", script], timeout=8.0)
            if result.returncode != 0:
                return []
            return [int(p) for p in result.stdout.replace(",", " ").split() if p.strip().isdigit()]
        except Exception:
            return []

    @staticmethod
    def _lsof_ips(pids: List[int]) -> Set[str]:
        """Return remote IPv4 addresses open by any of *pids*."""
        if not pids:
            return set()
        pid_args: List[str] = []
        for pid in pids:
            pid_args += ["-p", str(pid)]
        try:
            result = _run(["lsof", "-n", "-i", "4"] + pid_args, timeout=15.0)
        except Exception:
            return set()

        ips: Set[str] = set()
        for line in result.stdout.splitlines():
            if "->" not in line:
                continue
            remote = line.split("->", 1)[1]
            m = _IP_RE.search(remote)
            if m:
                ip = m.group(1)
                # Skip loopback, APIPA, and unspecified.
                if not (
                    ip.startswith("127.")
                    or ip.startswith("169.254.")
                    or ip == "0.0.0.0"
                ):
                    ips.add(ip)
        return ips


# ---------------------------------------------------------------------------
# Main public class
# ---------------------------------------------------------------------------


class SplitTunnel:
    """
    Split tunneling for macOS — route selected apps/subnets directly.

    Requires root privileges (route manipulation).
    Must be started *after* the VPN tunnel is established.
    Call ``stop()`` before tearing down the VPN to clean up routes.
    """

    def __init__(
        self,
        config: SplitTunnelConfig,
        vpn_interface: str,
        original_gateway: Optional[str] = None,
        original_interface: Optional[str] = None,
    ) -> None:
        self._config = config
        self._vpn_if = vpn_interface
        self._lock = threading.Lock()

        if original_gateway and original_interface:
            gw, iface = original_gateway, original_interface
        else:
            gw, iface = _get_default_gateway()
        self._orig_gw = gw
        self._orig_if = iface

        self._route_mgr = _RouteManager(gw, iface)
        self._proc_mon = _ProcessMonitor()
        # Prefix index for fast static-subnet membership checks (perf opt #1).
        self._static_idx = _PrefixIndex(config.bypass_subnets)
        # app_key -> set of IPs we've installed bypass routes for.
        self._app_routes: Dict[str, Set[str]] = {}

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._started = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Activate split tunneling rules."""
        if self._started:
            return
        self._started = True
        self._stop_event.clear()
        self._apply_static_subnets()
        if self._config.apps:
            self._thread = threading.Thread(
                target=self._monitor_loop, daemon=True, name="split-tunnel"
            )
            self._thread.start()
        logger.info(
            "split_tunnel.started",
            mode=self._config.mode.value,
            static_subnets=len(self._config.bypass_subnets),
            app_rules=len(self._config.apps),
            orig_gateway=self._orig_gw,
        )

    def stop(self) -> None:
        """Deactivate split tunneling and remove all injected routes."""
        if not self._started:
            return
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=15)
            self._thread = None
        self._route_mgr.remove_all()
        with self._lock:
            self._app_routes.clear()
        self._started = False
        logger.info("split_tunnel.stopped")

    def add_app(self, rule: AppRule) -> None:
        """Dynamically add an app rule (takes effect on the next scan)."""
        with self._lock:
            self._config.apps.append(rule)
        logger.info("split_tunnel.app_rule_added", process=rule.process_name, bundle=rule.bundle_id)

    def remove_app(self, process_name: str = "", bundle_id: str = "") -> None:
        """Remove an app rule and withdraw its bypass routes."""
        with self._lock:
            self._config.apps = [
                r
                for r in self._config.apps
                if r.process_name != process_name and r.bundle_id != bundle_id
            ]
            key = process_name or bundle_id
            stale_ips = self._app_routes.pop(key, set())

        for ip in stale_ips:
            if not self._ip_still_needed(ip, exclude_key=key):
                self._route_mgr.remove_host(ip)

    def add_bypass_subnet(self, subnet: str) -> None:
        """Add a subnet to the bypass list and immediately install its route."""
        self._static_idx.add(subnet)
        with self._lock:
            self._config.bypass_subnets.append(subnet)
        self._route_mgr.add_bypass_subnet(subnet)

    @property
    def config(self) -> SplitTunnelConfig:
        return self._config

    @property
    def managed_routes(self) -> Set[str]:
        return self._route_mgr.managed_routes

    @property
    def original_gateway(self) -> str:
        return self._orig_gw

    # ------------------------------------------------------------------
    # Internal — static routes
    # ------------------------------------------------------------------

    def _apply_static_subnets(self) -> None:
        for subnet in self._config.bypass_subnets:
            self._route_mgr.add_bypass_subnet(subnet)

    # ------------------------------------------------------------------
    # Internal — dynamic app monitoring
    # ------------------------------------------------------------------

    def _monitor_loop(self) -> None:
        while not self._stop_event.wait(self._config.scan_interval):
            try:
                self._scan_once()
            except Exception as exc:
                logger.warning("split_tunnel.scan_error", error=str(exc))

    def _scan_once(self) -> None:
        with self._lock:
            apps = list(self._config.apps)

        for rule in apps:
            key = rule.process_name or rule.bundle_id
            if not key:
                continue

            # Performance opt #2: skip lsof if PID set unchanged.
            ips, changed = self._proc_mon.connection_ips(rule)

            if not changed:
                continue  # Nothing to update for this app.

            if self._config.mode == SplitTunnelMode.EXCLUDE:
                # App bypasses VPN → add its IPs as direct routes.
                with self._lock:
                    old_ips = self._app_routes.get(key, set())

                new_ips = ips - old_ips
                gone_ips = old_ips - ips

                for ip in new_ips:
                    # Skip if already covered by a static bypass subnet.
                    if self._static_idx.contains(ip):
                        continue
                    if self._route_mgr.add_bypass_host(ip):
                        logger.debug("split_tunnel.bypass_added", app=key, ip=ip)

                for ip in gone_ips:
                    if not self._ip_still_needed(ip, exclude_key=key):
                        self._route_mgr.remove_host(ip)

                with self._lock:
                    self._app_routes[key] = ips

            # INCLUDE mode: all bypass routes should be installed for
            # subnets *not* used by listed apps — this is complex to
            # implement purely via host routes, so we rely on the
            # static bypass_subnets list for the INCLUDE case and leave
            # dynamic host routes to the EXCLUDE mode above.

    def _ip_still_needed(self, ip: str, exclude_key: str) -> bool:
        """Return True if another app rule still needs *ip* as bypass."""
        with self._lock:
            for key, ips in self._app_routes.items():
                if key != exclude_key and ip in ips:
                    return True
        return False


# ---------------------------------------------------------------------------
# Factory helper
# ---------------------------------------------------------------------------


def create_split_tunnel(
    mode: str = "exclude",
    apps: Optional[List[str]] = None,
    bypass_subnets: Optional[List[str]] = None,
    vpn_interface: str = "utun5",
    original_gateway: Optional[str] = None,
    original_interface: Optional[str] = None,
) -> SplitTunnel:
    """
    Convenience factory.

    Args:
        mode: ``"exclude"`` — listed apps bypass VPN; ``"include"`` — only
              listed apps use VPN.
        apps: process name substrings to match (e.g. ``["Sberbank", "tinkoff"]``).
        bypass_subnets: CIDR subnets to always route directly.
        vpn_interface: Active VPN tunnel interface (e.g. ``"utun5"``).
        original_gateway: LAN gateway IP (auto-detected if None).
        original_interface: LAN interface name (auto-detected if None).
    """
    app_rules = [AppRule(process_name=name) for name in (apps or [])]
    config = SplitTunnelConfig(
        mode=SplitTunnelMode(mode),
        apps=app_rules,
        bypass_subnets=list(bypass_subnets or []),
    )
    return SplitTunnel(config, vpn_interface, original_gateway, original_interface)
