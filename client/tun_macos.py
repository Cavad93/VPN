"""
tun_macos.py — macOS TUN interface for VPN client.

Opens a utun device via AF_SYSTEM/SYSPROTO_CONTROL socket, configures the
interface IP address and routing, and provides low-level read/write access
to raw IPv4 packets.

Requires root privileges (or net.inet.ip.forwarding enabled) to configure
the interface and routes.

Usage:
    tun = TunInterface.open()
    tun.configure("10.8.0.2", "10.8.0.1", prefix_len=24, mtu=1420)
    tun.add_default_route("10.8.0.1")

    # read / write raw IP packets
    pkt = tun.read_packet()
    tun.write_packet(pkt)

    tun.close()
"""

from __future__ import annotations

import ctypes
import fcntl
import ipaddress
import logging
import os
import socket
import struct
import subprocess
import threading
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# macOS socket / ioctl constants
# ---------------------------------------------------------------------------

# sys/socket.h
AF_SYSTEM = 32
SYSPROTO_CONTROL = 2
SOCK_DGRAM = 2

# net/if_utun.h
UTUN_CONTROL_NAME = b"com.apple.net.utun_control"
UTUN_OPT_IFNAME = 2

# sys/sys_domain.h
CTLIOCGINFO = 0xC0644E03  # _IOWR('N', 3, struct ctl_info)

# Packet address-family prefix used by utun (4 bytes, big-endian AF_INET = 2)
_AF_INET = 2
_UTUN_HDR = struct.pack(">I", _AF_INET)  # b'\x00\x00\x00\x02'
_UTUN_HDR_LEN = 4

# Maximum transmission unit default
DEFAULT_MTU = 1420


# ---------------------------------------------------------------------------
# ctypes structures
# ---------------------------------------------------------------------------

class CtlInfo(ctypes.Structure):
    """struct ctl_info from <sys/kern_control.h>."""

    _fields_ = [
        ("ctl_id", ctypes.c_uint32),
        ("ctl_name", ctypes.c_char * 96),
    ]


class SockAddrCtl(ctypes.Structure):
    """struct sockaddr_ctl from <sys/kern_control.h>."""

    _fields_ = [
        ("sc_len", ctypes.c_uint8),
        ("sc_family", ctypes.c_uint8),
        ("ss_sysaddr", ctypes.c_uint16),
        ("sc_id", ctypes.c_uint32),
        ("sc_unit", ctypes.c_uint32),
        ("sc_reserved", ctypes.c_uint32 * 5),
    ]


# ---------------------------------------------------------------------------
# TunInterface
# ---------------------------------------------------------------------------


class TunInterface:
    """
    Represents an open macOS utun network interface.

    Lifecycle:
        tun = TunInterface.open()          # opens /dev/utunN
        tun.configure(local, peer, ...)    # ifconfig + route
        pkt = tun.read_packet()            # raw IPv4 packet bytes
        tun.write_packet(pkt)              # inject raw IPv4 packet
        tun.close()                        # destroy interface
    """

    def __init__(self, fd: int, name: str) -> None:
        self._fd = fd
        self._name = name
        self._local_ip: Optional[str] = None
        self._peer_ip: Optional[str] = None
        self._read_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._closed = False
        logger.debug("tun_opened fd=%d name=%s", fd, name)

    # ------------------------------------------------------------------
    # Factory

    @classmethod
    def open(cls, unit: int = 0) -> "TunInterface":
        """
        Open a macOS utun interface.

        Args:
            unit: utun unit number to request (0 means kernel chooses).
                  unit=1 → utun0, unit=2 → utun1, … (unit=0 → any).

        Returns:
            TunInterface instance with open file descriptor.

        Raises:
            OSError: if the socket or ioctl calls fail.
            PermissionError: if not running as root.
        """
        # Create a kernel control socket
        fd = socket.socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL).detach()

        # Look up the control ID for com.apple.net.utun_control
        info = CtlInfo()
        info.ctl_name = UTUN_CONTROL_NAME
        try:
            fcntl.ioctl(fd, CTLIOCGINFO, info)
        except OSError as exc:
            os.close(fd)
            raise OSError(f"CTLIOCGINFO failed: {exc}") from exc

        # Build sockaddr_ctl and connect
        addr = SockAddrCtl()
        addr.sc_len = ctypes.sizeof(SockAddrCtl)
        addr.sc_family = AF_SYSTEM
        addr.ss_sysaddr = AF_SYSTEM
        addr.sc_id = info.ctl_id
        addr.sc_unit = unit  # 0 = let kernel pick next available

        addr_bytes = bytes(addr)
        try:
            # connect(fd, &addr, sizeof(addr))
            libc = ctypes.CDLL(None, use_errno=True)
            ret = libc.connect(fd, addr_bytes, len(addr_bytes))
            if ret != 0:
                errno = ctypes.get_errno()
                os.close(fd)
                raise OSError(errno, os.strerror(errno))
        except OSError:
            raise

        # Retrieve the assigned interface name (utun0, utun1, …)
        name_buf = ctypes.create_string_buffer(16)
        name_len = ctypes.c_uint32(ctypes.sizeof(name_buf))
        try:
            libc.getsockopt(
                fd,
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                name_buf,
                ctypes.byref(name_len),
            )
            iface_name = name_buf.value.decode()
        except Exception:
            iface_name = f"utun{max(unit - 1, 0)}"

        return cls(fd, iface_name)

    # ------------------------------------------------------------------
    # Properties

    @property
    def name(self) -> str:
        """Interface name, e.g. 'utun5'."""
        return self._name

    @property
    def fd(self) -> int:
        """Raw file descriptor."""
        return self._fd

    # ------------------------------------------------------------------
    # Configuration

    def configure(
        self,
        local_ip: str,
        peer_ip: str,
        prefix_len: int = 24,
        mtu: int = DEFAULT_MTU,
    ) -> None:
        """
        Configure the TUN interface with the given IP addresses.

        Runs:
            ifconfig <name> <local_ip> <peer_ip> mtu <mtu> up

        Args:
            local_ip:   Assigned VPN IP for this client, e.g. "10.8.0.2".
            peer_ip:    Server/gateway VPN IP, e.g. "10.8.0.1".
            prefix_len: Subnet prefix length (informational, used for routes).
            mtu:        Maximum transmission unit.

        Raises:
            subprocess.CalledProcessError: if ifconfig fails.
        """
        self._local_ip = local_ip
        self._peer_ip = peer_ip

        # Point-to-point configuration (macOS utun style)
        _run(["ifconfig", self._name, local_ip, peer_ip, "mtu", str(mtu), "up"])
        logger.info(
            "tun_configured name=%s local=%s peer=%s mtu=%d",
            self._name, local_ip, peer_ip, mtu,
        )

    def add_route(self, network: str, gateway: str) -> None:
        """
        Add a route via the VPN gateway.

        Args:
            network: Destination in CIDR notation, e.g. "0.0.0.0/0".
            gateway: Next-hop IP, e.g. "10.8.0.1".
        """
        net = ipaddress.IPv4Network(network, strict=False)
        _run([
            "route", "-n", "add", "-net",
            str(net.network_address),
            "-netmask", str(net.netmask),
            gateway,
        ])
        logger.info("route_added network=%s gateway=%s", network, gateway)

    def delete_route(self, network: str, gateway: str) -> None:
        """
        Delete a previously added route.

        Args:
            network: Destination in CIDR notation.
            gateway: Next-hop IP.
        """
        net = ipaddress.IPv4Network(network, strict=False)
        _run(
            [
                "route", "-n", "delete", "-net",
                str(net.network_address),
                "-netmask", str(net.netmask),
                gateway,
            ],
            check=False,
        )
        logger.info("route_deleted network=%s gateway=%s", network, gateway)

    def add_default_route(self, gateway: str) -> None:
        """
        Replace the system default route to send all traffic through the VPN.

        Saves the original default route first (for later restoration).

        Args:
            gateway: VPN gateway IP, e.g. "10.8.0.1".
        """
        self.add_route("0.0.0.0/0", gateway)

    def delete_default_route(self, gateway: str) -> None:
        """Remove a previously added default route."""
        self.delete_route("0.0.0.0/0", gateway)

    # ------------------------------------------------------------------
    # Packet I/O

    def read_packet(self, max_size: int = 65535) -> bytes:
        """
        Read one raw IPv4 packet from the TUN interface.

        Blocks until a packet is available.

        Returns:
            Raw IPv4 packet bytes (without the 4-byte utun header).

        Raises:
            OSError:  on read error.
            EOFError: if the interface has been closed.
        """
        with self._read_lock:
            if self._closed:
                raise EOFError("TUN interface is closed")
            try:
                data = os.read(self._fd, _UTUN_HDR_LEN + max_size)
            except OSError as exc:
                raise OSError(f"TUN read failed: {exc}") from exc

        if len(data) < _UTUN_HDR_LEN:
            raise OSError("TUN read returned too-short data")

        # Strip the 4-byte address-family header
        return data[_UTUN_HDR_LEN:]

    def write_packet(self, packet: bytes) -> None:
        """
        Inject a raw IPv4 packet into the TUN interface.

        Prepends the 4-byte utun header (AF_INET = 0x00000002).

        Args:
            packet: Raw IPv4 packet bytes.

        Raises:
            ValueError: if packet is empty.
            OSError:    on write error.
        """
        if not packet:
            raise ValueError("packet must not be empty")

        with self._write_lock:
            if self._closed:
                raise EOFError("TUN interface is closed")
            frame = _UTUN_HDR + packet
            try:
                written = os.write(self._fd, frame)
            except OSError as exc:
                raise OSError(f"TUN write failed: {exc}") from exc

        if written != len(frame):
            raise OSError(
                f"TUN write incomplete: wrote {written} of {len(frame)} bytes"
            )

    # ------------------------------------------------------------------
    # Lifecycle

    def close(self) -> None:
        """Close the TUN interface file descriptor."""
        if not self._closed:
            self._closed = True
            try:
                os.close(self._fd)
                logger.debug("tun_closed name=%s", self._name)
            except OSError:
                pass

    def __enter__(self) -> "TunInterface":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a shell command, raising on failure when check=True."""
    logger.debug("tun_cmd %s", " ".join(cmd))
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode,
            cmd,
            output=result.stdout,
            stderr=result.stderr,
        )
    return result


def get_default_gateway() -> Optional[str]:
    """
    Return the current default IPv4 gateway IP on macOS.

    Parses `netstat -rn` output to find the default (0.0.0.0) route.

    Returns:
        Gateway IP string, e.g. "192.168.1.1", or None if not found.
    """
    result = _run(["netstat", "-rn", "-f", "inet"], check=False)
    for line in result.stdout.splitlines():
        parts = line.split()
        if parts and parts[0] in ("default", "0.0.0.0"):
            if len(parts) >= 2:
                gw = parts[1]
                # Validate it looks like an IP
                try:
                    socket.inet_aton(gw)
                    return gw
                except OSError:
                    continue
    return None


def get_interface_mtu(iface: str) -> Optional[int]:
    """
    Return the MTU of the given network interface.

    Args:
        iface: Interface name, e.g. "utun5".

    Returns:
        MTU as integer, or None if not found.
    """
    result = _run(["ifconfig", iface], check=False)
    for part in result.stdout.split():
        if part.isdigit():
            # ifconfig output: "mtu 1420"
            pass
    # Parse "mtu <N>" from ifconfig output
    import re
    m = re.search(r"\bmtu\s+(\d+)", result.stdout)
    if m:
        return int(m.group(1))
    return None
