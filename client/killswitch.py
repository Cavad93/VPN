"""
killswitch.py — VPN Kill Switch for macOS.

Blocks ALL outbound traffic when the VPN tunnel is down, preventing
data leaks. Uses macOS Packet Filter (pfctl) to insert firewall rules
that allow only:
  - loopback traffic
  - traffic to/from the VPN server IP (so reconnect is possible)
  - traffic through the VPN tunnel interface (utun*)
  - DHCP traffic (UDP 67/68) to maintain IP lease

On stop() or context-manager __exit__, original PF state is restored.

Requires root privileges (sudo or running as root).
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import threading
from typing import Optional

import structlog

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# PF anchor name used exclusively by this module
# ---------------------------------------------------------------------------
_ANCHOR = "com.cavadvpn.killswitch"

# ---------------------------------------------------------------------------
# PF rule template
# ---------------------------------------------------------------------------
# Rules inserted into the anchor when kill switch is active.
# {vpn_iface}    — TUN interface name, e.g. "utun3"
# {server_ip}    — VPN server IP, e.g. "193.124.93.240"
_RULES_TEMPLATE = """\
# CavadVPN kill switch rules — auto-generated, do not edit manually
# Allow loopback
pass quick on lo0 all

# Allow DHCP so we can maintain/renew our LAN address
pass quick proto udp from any port 68 to any port 67
pass quick proto udp from any port 67 to any port 68

# Allow traffic to/from the VPN server so reconnect is possible
pass quick proto tcp from any to {server_ip}
pass quick proto udp from any to {server_ip}
pass quick proto tcp from {server_ip} to any
pass quick proto udp from {server_ip} to any

# Allow all traffic through the VPN tunnel interface
pass quick on {vpn_iface} all

# Block everything else
block drop all
"""


def _run(cmd: list[str], *, check: bool = True, input: Optional[str] = None) -> subprocess.CompletedProcess:
    """Run a system command, logging on error."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            input=input,
            check=check,
        )
        return result
    except subprocess.CalledProcessError as exc:
        logger.error(
            "command_failed",
            cmd=" ".join(cmd),
            returncode=exc.returncode,
            stderr=exc.stderr.strip(),
        )
        raise


# ---------------------------------------------------------------------------
# Low-level pfctl helpers
# ---------------------------------------------------------------------------


def _anchor_exists() -> bool:
    """Return True if our PF anchor is currently loaded."""
    result = _run(["pfctl", "-a", _ANCHOR, "-s", "rules"], check=False)
    return result.returncode == 0 and result.stdout.strip() != ""


def _load_anchor_rules(rules: str) -> None:
    """Load *rules* string into the PF anchor."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".pf", delete=False) as fh:
        fh.write(rules)
        tmp_path = fh.name

    _run(["pfctl", "-a", _ANCHOR, "-f", tmp_path])
    os.unlink(tmp_path)


def _flush_anchor() -> None:
    """Remove all rules from our PF anchor."""
    _run(["pfctl", "-a", _ANCHOR, "-F", "rules"], check=False)


def _enable_pf() -> None:
    """Enable PF if not already running."""
    result = _run(["pfctl", "-s", "info"], check=False)
    if result.returncode != 0 or "Enabled" not in result.stdout:
        _run(["pfctl", "-e"], check=False)


def _get_pf_enabled() -> bool:
    """Return whether PF is currently enabled."""
    result = _run(["pfctl", "-s", "info"], check=False)
    return result.returncode == 0 and "Enabled" in result.stdout


def _get_anchor_rules() -> str:
    """Return current rules loaded in our anchor (empty string if none)."""
    result = _run(["pfctl", "-a", _ANCHOR, "-s", "rules"], check=False)
    if result.returncode == 0:
        return result.stdout
    return ""


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class KillSwitch:
    """
    macOS VPN Kill Switch using Packet Filter (pfctl).

    Usage::

        ks = KillSwitch()
        ks.start(vpn_interface="utun3", server_ip="193.124.93.240")
        # ... VPN is up; all other traffic blocked ...
        ks.stop()

    Or as a context manager::

        with KillSwitch() as ks:
            ks.start("utun3", "193.124.93.240")
            # ...
        # rules removed automatically on exit

    Thread-safe: start/stop may be called from any thread.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._active = False
        self._vpn_interface: Optional[str] = None
        self._server_ip: Optional[str] = None
        # Remember whether PF was already enabled before we touched it
        self._pf_was_enabled: bool = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def active(self) -> bool:
        """True if the kill switch is currently engaged."""
        return self._active

    @property
    def vpn_interface(self) -> Optional[str]:
        """TUN interface name passed to start()."""
        return self._vpn_interface

    @property
    def server_ip(self) -> Optional[str]:
        """VPN server IP passed to start()."""
        return self._server_ip

    def start(self, vpn_interface: str, server_ip: str) -> None:
        """
        Engage the kill switch.

        Loads PF anchor rules that block all traffic except loopback,
        DHCP, the VPN server IP, and the VPN tunnel interface.

        Args:
            vpn_interface: Name of the TUN interface (e.g. "utun3").
            server_ip:     IP address of the VPN server.

        Raises:
            RuntimeError: If already active.
            subprocess.CalledProcessError: If pfctl fails (needs root).
        """
        with self._lock:
            if self._active:
                raise RuntimeError("Kill switch is already active")

            logger.info(
                "killswitch_starting",
                vpn_interface=vpn_interface,
                server_ip=server_ip,
            )

            self._pf_was_enabled = _get_pf_enabled()
            _enable_pf()

            rules = _RULES_TEMPLATE.format(
                vpn_iface=vpn_interface,
                server_ip=server_ip,
            )
            _load_anchor_rules(rules)

            self._active = True
            self._vpn_interface = vpn_interface
            self._server_ip = server_ip

            logger.info(
                "killswitch_active",
                vpn_interface=vpn_interface,
                server_ip=server_ip,
            )

    def stop(self) -> None:
        """
        Disengage the kill switch.

        Removes all rules from the PF anchor. If PF was not enabled
        before start() was called, it is disabled again.

        Safe to call even if not active (no-op).
        """
        with self._lock:
            if not self._active:
                logger.debug("killswitch_stop_noop")
                return

            logger.info("killswitch_stopping")

            _flush_anchor()

            if not self._pf_was_enabled:
                _run(["pfctl", "-d"], check=False)

            self._active = False
            self._vpn_interface = None
            self._server_ip = None

            logger.info("killswitch_stopped")

    def update(self, vpn_interface: Optional[str] = None, server_ip: Optional[str] = None) -> None:
        """
        Update the active kill switch rules without a full stop/start cycle.

        Args:
            vpn_interface: New TUN interface name (or None to keep current).
            server_ip:     New server IP (or None to keep current).

        Raises:
            RuntimeError: If kill switch is not active.
        """
        with self._lock:
            if not self._active:
                raise RuntimeError("Kill switch is not active; call start() first")

            new_iface = vpn_interface if vpn_interface is not None else self._vpn_interface
            new_ip = server_ip if server_ip is not None else self._server_ip

            rules = _RULES_TEMPLATE.format(vpn_iface=new_iface, server_ip=new_ip)
            _load_anchor_rules(rules)

            self._vpn_interface = new_iface
            self._server_ip = new_ip

            logger.info(
                "killswitch_updated",
                vpn_interface=new_iface,
                server_ip=new_ip,
            )

    def get_current_rules(self) -> str:
        """
        Return the currently loaded PF anchor rules as a string.

        Returns an empty string if the kill switch is not active.
        """
        if not self._active:
            return ""
        return _get_anchor_rules()

    # ------------------------------------------------------------------
    # Context-manager support
    # ------------------------------------------------------------------

    def __enter__(self) -> "KillSwitch":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------


def create_kill_switch() -> KillSwitch:
    """
    Factory function — returns a new KillSwitch instance.

    Equivalent to ``KillSwitch()``, provided for symmetry with
    other modules that use factory functions.
    """
    return KillSwitch()
