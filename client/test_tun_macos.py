"""
test_tun_macos.py — Unit tests for tun_macos.py.

Tests that do not require root or a real macOS environment use mocking to
simulate OS calls. Tests that require root/macOS are skipped automatically
when not available.
"""

from __future__ import annotations

import os
import struct
import subprocess
import sys
import threading
import unittest
from unittest.mock import MagicMock, patch, call

# The module under test
import tun_macos
from tun_macos import (
    TunInterface,
    _AF_INET,
    _UTUN_HDR,
    _UTUN_HDR_LEN,
    DEFAULT_MTU,
    _run,
    get_default_gateway,
    get_interface_mtu,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_tun(fd: int = 5, name: str = "utun5") -> TunInterface:
    """Return a TunInterface backed by a fake fd (no OS calls)."""
    return TunInterface(fd, name)


# ---------------------------------------------------------------------------
# TunInterface — basic properties
# ---------------------------------------------------------------------------


class TestTunInterfaceProperties(unittest.TestCase):
    def test_name(self) -> None:
        tun = _make_tun(name="utun3")
        self.assertEqual(tun.name, "utun3")

    def test_fd(self) -> None:
        tun = _make_tun(fd=7)
        self.assertEqual(tun.fd, 7)

    def test_not_closed_on_create(self) -> None:
        tun = _make_tun()
        self.assertFalse(tun._closed)


# ---------------------------------------------------------------------------
# TunInterface — close
# ---------------------------------------------------------------------------


class TestTunClose(unittest.TestCase):
    def test_close_calls_os_close(self) -> None:
        tun = _make_tun(fd=42)
        with patch("os.close") as mock_close:
            tun.close()
        mock_close.assert_called_once_with(42)
        self.assertTrue(tun._closed)

    def test_double_close_is_safe(self) -> None:
        tun = _make_tun(fd=42)
        with patch("os.close") as mock_close:
            tun.close()
            tun.close()
        # os.close should only be called once
        mock_close.assert_called_once()

    def test_context_manager(self) -> None:
        tun = _make_tun(fd=9)
        with patch("os.close") as mock_close:
            with tun:
                pass
        mock_close.assert_called_once_with(9)


# ---------------------------------------------------------------------------
# TunInterface — write_packet
# ---------------------------------------------------------------------------


class TestTunWritePacket(unittest.TestCase):
    def test_write_prepends_utun_header(self) -> None:
        tun = _make_tun(fd=10)
        pkt = b"\x45\x00\x00\x28" + b"\x00" * 36  # minimal IPv4-like payload

        with patch("os.write", return_value=len(_UTUN_HDR) + len(pkt)) as mock_write:
            tun.write_packet(pkt)

        expected_frame = _UTUN_HDR + pkt
        mock_write.assert_called_once_with(10, expected_frame)

    def test_write_raises_on_empty_packet(self) -> None:
        tun = _make_tun()
        with self.assertRaises(ValueError):
            tun.write_packet(b"")

    def test_write_raises_on_closed(self) -> None:
        tun = _make_tun(fd=10)
        tun._closed = True
        with self.assertRaises(EOFError):
            tun.write_packet(b"\x45" + b"\x00" * 19)

    def test_write_raises_on_incomplete_write(self) -> None:
        tun = _make_tun(fd=10)
        pkt = b"\x45" + b"\x00" * 19
        # Simulate partial write: only 1 byte written
        with patch("os.write", return_value=1):
            with self.assertRaises(OSError):
                tun.write_packet(pkt)

    def test_write_propagates_os_error(self) -> None:
        tun = _make_tun(fd=10)
        pkt = b"\x45" + b"\x00" * 19
        with patch("os.write", side_effect=OSError("broken pipe")):
            with self.assertRaises(OSError):
                tun.write_packet(pkt)

    def test_utun_header_constant(self) -> None:
        """The utun header must be big-endian AF_INET (2)."""
        self.assertEqual(_UTUN_HDR, struct.pack(">I", 2))
        self.assertEqual(_UTUN_HDR_LEN, 4)


# ---------------------------------------------------------------------------
# TunInterface — read_packet
# ---------------------------------------------------------------------------


class TestTunReadPacket(unittest.TestCase):
    def test_read_strips_utun_header(self) -> None:
        tun = _make_tun(fd=11)
        ip_payload = b"\x45\x00\x00\x28" + b"\xAB" * 36
        raw = _UTUN_HDR + ip_payload

        with patch("os.read", return_value=raw):
            result = tun.read_packet()

        self.assertEqual(result, ip_payload)

    def test_read_raises_on_closed(self) -> None:
        tun = _make_tun(fd=11)
        tun._closed = True
        with self.assertRaises(EOFError):
            tun.read_packet()

    def test_read_raises_on_short_data(self) -> None:
        tun = _make_tun(fd=11)
        # Return only 3 bytes — less than the 4-byte header
        with patch("os.read", return_value=b"\x00\x00\x00"):
            with self.assertRaises(OSError):
                tun.read_packet()

    def test_read_propagates_os_error(self) -> None:
        tun = _make_tun(fd=11)
        with patch("os.read", side_effect=OSError("IO error")):
            with self.assertRaises(OSError):
                tun.read_packet()

    def test_read_uses_max_size(self) -> None:
        tun = _make_tun(fd=11)
        ip_payload = b"\x45" + b"\x00" * 19
        raw = _UTUN_HDR + ip_payload

        with patch("os.read", return_value=raw) as mock_read:
            tun.read_packet(max_size=9000)

        mock_read.assert_called_once_with(11, _UTUN_HDR_LEN + 9000)


# ---------------------------------------------------------------------------
# TunInterface — configure
# ---------------------------------------------------------------------------


class TestTunConfigure(unittest.TestCase):
    def test_configure_calls_ifconfig(self) -> None:
        tun = _make_tun(name="utun5")
        with patch("tun_macos._run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            tun.configure("10.8.0.2", "10.8.0.1", prefix_len=24, mtu=1420)

        mock_run.assert_called_once_with(
            ["ifconfig", "utun5", "10.8.0.2", "10.8.0.1", "mtu", "1420", "up"]
        )

    def test_configure_stores_ips(self) -> None:
        tun = _make_tun(name="utun5")
        with patch("tun_macos._run"):
            tun.configure("10.8.0.2", "10.8.0.1")

        self.assertEqual(tun._local_ip, "10.8.0.2")
        self.assertEqual(tun._peer_ip, "10.8.0.1")

    def test_configure_default_mtu(self) -> None:
        tun = _make_tun(name="utun5")
        with patch("tun_macos._run") as mock_run:
            tun.configure("10.0.0.2", "10.0.0.1")

        args = mock_run.call_args[0][0]
        self.assertIn(str(DEFAULT_MTU), args)


# ---------------------------------------------------------------------------
# TunInterface — routes
# ---------------------------------------------------------------------------


class TestTunRoutes(unittest.TestCase):
    def test_add_route(self) -> None:
        tun = _make_tun(name="utun5")
        with patch("tun_macos._run") as mock_run:
            tun.add_route("192.168.100.0/24", "10.8.0.1")

        mock_run.assert_called_once_with([
            "route", "-n", "add", "-net",
            "192.168.100.0", "-netmask", "255.255.255.0",
            "10.8.0.1",
        ])

    def test_delete_route(self) -> None:
        tun = _make_tun(name="utun5")
        with patch("tun_macos._run") as mock_run:
            tun.delete_route("192.168.100.0/24", "10.8.0.1")

        mock_run.assert_called_once_with(
            [
                "route", "-n", "delete", "-net",
                "192.168.100.0", "-netmask", "255.255.255.0",
                "10.8.0.1",
            ],
            check=False,
        )

    def test_add_default_route(self) -> None:
        tun = _make_tun()
        with patch.object(tun, "add_route") as mock_add:
            tun.add_default_route("10.8.0.1")

        mock_add.assert_called_once_with("0.0.0.0/0", "10.8.0.1")

    def test_delete_default_route(self) -> None:
        tun = _make_tun()
        with patch.object(tun, "delete_route") as mock_del:
            tun.delete_default_route("10.8.0.1")

        mock_del.assert_called_once_with("0.0.0.0/0", "10.8.0.1")

    def test_add_route_host_mask(self) -> None:
        """A /32 route should use netmask 255.255.255.255."""
        tun = _make_tun()
        with patch("tun_macos._run") as mock_run:
            tun.add_route("8.8.8.8/32", "10.8.0.1")

        args = mock_run.call_args[0][0]
        self.assertIn("255.255.255.255", args)

    def test_add_route_classless(self) -> None:
        """A /16 route should use netmask 255.255.0.0."""
        tun = _make_tun()
        with patch("tun_macos._run") as mock_run:
            tun.add_route("10.0.0.0/16", "10.8.0.1")

        args = mock_run.call_args[0][0]
        self.assertIn("255.255.0.0", args)


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------


class TestGetDefaultGateway(unittest.TestCase):
    _NETSTAT_OUTPUT = (
        "Routing tables\n\n"
        "Internet:\n"
        "Destination        Gateway            Flags\n"
        "default            192.168.1.1        UGScg\n"
        "127.0.0.1          127.0.0.1          UH\n"
    )

    def test_parses_gateway(self) -> None:
        mock_result = MagicMock()
        mock_result.stdout = self._NETSTAT_OUTPUT
        mock_result.returncode = 0

        with patch("tun_macos._run", return_value=mock_result):
            gw = get_default_gateway()

        self.assertEqual(gw, "192.168.1.1")

    def test_returns_none_when_no_default(self) -> None:
        mock_result = MagicMock()
        mock_result.stdout = "Routing tables\nInternet:\n"
        mock_result.returncode = 0

        with patch("tun_macos._run", return_value=mock_result):
            gw = get_default_gateway()

        self.assertIsNone(gw)

    def test_skips_non_ip_gateway(self) -> None:
        mock_result = MagicMock()
        mock_result.stdout = (
            "Routing tables\n\nInternet:\n"
            "default            link#5             UCSg\n"
        )
        mock_result.returncode = 0

        with patch("tun_macos._run", return_value=mock_result):
            gw = get_default_gateway()

        self.assertIsNone(gw)


class TestGetInterfaceMtu(unittest.TestCase):
    def test_parses_mtu(self) -> None:
        mock_result = MagicMock()
        mock_result.stdout = (
            "utun5: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1420\n"
            "        inet 10.8.0.2 --> 10.8.0.1 netmask 0xffffffff\n"
        )
        mock_result.returncode = 0

        with patch("tun_macos._run", return_value=mock_result):
            mtu = get_interface_mtu("utun5")

        self.assertEqual(mtu, 1420)

    def test_returns_none_when_not_found(self) -> None:
        mock_result = MagicMock()
        mock_result.stdout = "utun5: flags=8051<UP>\n"
        mock_result.returncode = 0

        with patch("tun_macos._run", return_value=mock_result):
            mtu = get_interface_mtu("utun5")

        self.assertIsNone(mtu)


# ---------------------------------------------------------------------------
# _run helper
# ---------------------------------------------------------------------------


class TestRunHelper(unittest.TestCase):
    def test_run_success(self) -> None:
        result = _run(["echo", "hello"], check=True)
        self.assertEqual(result.returncode, 0)

    def test_run_check_false_no_raise(self) -> None:
        result = _run(["false"], check=False)
        self.assertNotEqual(result.returncode, 0)

    def test_run_check_true_raises(self) -> None:
        with self.assertRaises(subprocess.CalledProcessError):
            _run(["false"], check=True)


# ---------------------------------------------------------------------------
# Thread-safety: concurrent reads and writes
# ---------------------------------------------------------------------------


class TestTunThreadSafety(unittest.TestCase):
    def test_concurrent_writes(self) -> None:
        """Multiple threads can call write_packet without data corruption."""
        tun = _make_tun(fd=20)
        written: list[bytes] = []
        lock = threading.Lock()

        def fake_write(fd: int, data: bytes) -> int:
            with lock:
                written.append(data)
            return len(data)

        with patch("os.write", side_effect=fake_write):
            threads = [
                threading.Thread(
                    target=tun.write_packet,
                    args=(bytes([0x45, 0x00, 0x00, 0x14 + i] + [0] * 16),),
                )
                for i in range(10)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        self.assertEqual(len(written), 10)
        # Each write must start with the utun header
        for frame in written:
            self.assertTrue(frame.startswith(_UTUN_HDR))

    def test_concurrent_reads(self) -> None:
        """Multiple threads can call read_packet safely."""
        tun = _make_tun(fd=21)
        ip_pkt = b"\x45" + b"\x00" * 19
        raw = _UTUN_HDR + ip_pkt
        results: list[bytes] = []
        lock = threading.Lock()

        def fake_read(fd: int, n: int) -> bytes:
            return raw

        def reader() -> None:
            pkt = tun.read_packet()
            with lock:
                results.append(pkt)

        with patch("os.read", side_effect=fake_read):
            threads = [threading.Thread(target=reader) for _ in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        self.assertEqual(len(results), 5)
        for pkt in results:
            self.assertEqual(pkt, ip_pkt)


if __name__ == "__main__":
    unittest.main()
