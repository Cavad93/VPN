"""
test_dns.py — unit tests for client/dns.py (DNS leak protection).

All system calls (networksetup, dscacheutil, etc.) are mocked so the
tests run without root privileges and without macOS.
"""

from __future__ import annotations

import subprocess
import textwrap
import threading
from dataclasses import dataclass
from typing import List, Optional
from unittest.mock import MagicMock, call, patch

import pytest

import dns as dns_mod
from dns import (
    DNSLeakProtection,
    DNSSnapshot,
    InterfaceDNS,
    _build_resolv_conf,
    _flush_dns_cache,
    _get_active_interfaces,
    _get_interface_dns,
    _read_resolv_conf,
    _run,
    _set_interface_dns,
    _write_resolv_conf,
    dns_protection_for_vpn,
    restore_snapshot,
    take_snapshot,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _completed(stdout: str = "", returncode: int = 0) -> subprocess.CompletedProcess:
    cp = subprocess.CompletedProcess(args=[], returncode=returncode)
    cp.stdout = stdout
    cp.stderr = ""
    return cp


# ---------------------------------------------------------------------------
# _run
# ---------------------------------------------------------------------------


class TestRun:
    def test_success(self):
        with patch("subprocess.run", return_value=_completed("hello")) as mock_run:
            result = _run(["echo", "hello"])
        assert result.stdout == "hello"
        mock_run.assert_called_once()

    def test_failure_raises(self):
        with patch("subprocess.run", return_value=_completed("", returncode=1)):
            with pytest.raises(RuntimeError):
                _run(["false"])

    def test_failure_no_raise_when_check_false(self):
        with patch("subprocess.run", return_value=_completed("", returncode=1)):
            result = _run(["false"], check=False)
        assert result.returncode == 1


# ---------------------------------------------------------------------------
# _get_active_interfaces
# ---------------------------------------------------------------------------


class TestGetActiveInterfaces:
    def test_parses_services(self):
        output = textwrap.dedent(
            """\
            An asterisk (*) denotes that a network service is disabled.
            Wi-Fi
            Ethernet
            * VPN (PPTP)
            Bluetooth PAN
            """
        )
        with patch("dns._run", return_value=_completed(output)):
            ifaces = _get_active_interfaces()
        assert ifaces == ["Wi-Fi", "Ethernet", "Bluetooth PAN"]

    def test_empty_output(self):
        with patch("dns._run", return_value=_completed("")):
            ifaces = _get_active_interfaces()
        assert ifaces == []


# ---------------------------------------------------------------------------
# _get_interface_dns
# ---------------------------------------------------------------------------


class TestGetInterfaceDns:
    def test_parses_servers(self):
        def fake_run(cmd, check=True):
            if "-getdnsservers" in cmd:
                return _completed("8.8.8.8\n8.8.4.4\n")
            if "-getsearchdomains" in cmd:
                return _completed("example.com\n")
            return _completed("")

        with patch("dns._run", side_effect=fake_run):
            result = _get_interface_dns("Wi-Fi")

        assert result.interface == "Wi-Fi"
        assert result.servers == ["8.8.8.8", "8.8.4.4"]
        assert result.search_domains == ["example.com"]

    def test_empty_dns(self):
        def fake_run(cmd, check=True):
            if "-getdnsservers" in cmd:
                return _completed("There aren't any DNS Servers set on Wi-Fi.\n")
            if "-getsearchdomains" in cmd:
                return _completed("There aren't any Search Domains set on Wi-Fi.\n")
            return _completed("")

        with patch("dns._run", side_effect=fake_run):
            result = _get_interface_dns("Wi-Fi")

        assert result.servers == []
        assert result.search_domains == []

    def test_ignores_non_ip_lines(self):
        def fake_run(cmd, check=True):
            if "-getdnsservers" in cmd:
                return _completed("1.1.1.1\nnot-an-ip\n2.2.2.2\n")
            return _completed("")

        with patch("dns._run", side_effect=fake_run):
            result = _get_interface_dns("Wi-Fi")

        assert result.servers == ["1.1.1.1", "2.2.2.2"]


# ---------------------------------------------------------------------------
# _set_interface_dns
# ---------------------------------------------------------------------------


class TestSetInterfaceDns:
    def test_sets_servers(self):
        calls = []
        with patch("dns._run", side_effect=lambda cmd, **kw: calls.append(cmd)):
            _set_interface_dns("Wi-Fi", ["10.8.0.1"])
        assert any("10.8.0.1" in " ".join(c) for c in calls)

    def test_empty_servers_passes_empty(self):
        calls = []
        with patch("dns._run", side_effect=lambda cmd, **kw: calls.append(cmd)):
            _set_interface_dns("Wi-Fi", [])
        assert any("empty" in c for c in calls[0])

    def test_sets_search_domains(self):
        calls = []
        with patch("dns._run", side_effect=lambda cmd, **kw: calls.append(cmd)):
            _set_interface_dns("Wi-Fi", ["10.8.0.1"], search_domains=["vpn.local"])
        assert any("vpn.local" in c for c in calls[-1])

    def test_empty_search_domains_passes_empty(self):
        calls = []
        with patch("dns._run", side_effect=lambda cmd, **kw: calls.append(cmd)):
            _set_interface_dns("Wi-Fi", ["10.8.0.1"], search_domains=[])
        assert any("empty" in c for c in calls[-1])

    def test_none_search_domains_not_called(self):
        calls = []
        with patch("dns._run", side_effect=lambda cmd, **kw: calls.append(cmd)):
            _set_interface_dns("Wi-Fi", ["10.8.0.1"], search_domains=None)
        assert not any("setsearchdomains" in " ".join(c) for c in calls)


# ---------------------------------------------------------------------------
# _read_resolv_conf / _write_resolv_conf
# ---------------------------------------------------------------------------


class TestResolvConf:
    def test_read_returns_content(self, tmp_path):
        p = tmp_path / "resolv.conf"
        p.write_text("nameserver 8.8.8.8\n")
        content = _read_resolv_conf(str(p))
        assert content == "nameserver 8.8.8.8\n"

    def test_read_missing_returns_none(self, tmp_path):
        content = _read_resolv_conf(str(tmp_path / "no_such_file"))
        assert content is None

    def test_write_and_read_roundtrip(self, tmp_path):
        p = tmp_path / "resolv.conf"
        _write_resolv_conf("nameserver 1.1.1.1\n", str(p))
        assert p.read_text() == "nameserver 1.1.1.1\n"


# ---------------------------------------------------------------------------
# _build_resolv_conf
# ---------------------------------------------------------------------------


class TestBuildResolvConf:
    def test_basic(self):
        content = _build_resolv_conf(["10.8.0.1", "8.8.8.8"], ["vpn.local"])
        assert "nameserver 10.8.0.1" in content
        assert "nameserver 8.8.8.8" in content
        assert "search vpn.local" in content

    def test_no_search_domains(self):
        content = _build_resolv_conf(["10.8.0.1"], [])
        assert "search" not in content
        assert "nameserver 10.8.0.1" in content

    def test_ends_with_newline(self):
        content = _build_resolv_conf(["1.1.1.1"], [])
        assert content.endswith("\n")


# ---------------------------------------------------------------------------
# _flush_dns_cache
# ---------------------------------------------------------------------------


class TestFlushDnsCache:
    def test_does_not_raise_on_error(self):
        with patch("dns._run", side_effect=RuntimeError("no dscacheutil")):
            # Should not propagate
            _flush_dns_cache()


# ---------------------------------------------------------------------------
# take_snapshot / restore_snapshot
# ---------------------------------------------------------------------------


class TestSnapshot:
    def _fake_run(self, cmd, check=True):
        if "-listallnetworkservices" in cmd:
            return _completed("Wi-Fi\nEthernet\n")
        if "-getdnsservers" in cmd:
            return _completed("8.8.8.8\n")
        if "-getsearchdomains" in cmd:
            return _completed("")
        return _completed("")

    def test_take_snapshot(self):
        with patch("dns._run", side_effect=self._fake_run):
            snap = take_snapshot()
        assert len(snap.interfaces) == 2
        assert snap.interfaces[0].servers == ["8.8.8.8"]

    def test_take_snapshot_explicit_ifaces(self):
        with patch("dns._run", side_effect=self._fake_run):
            snap = take_snapshot(["Wi-Fi"])
        assert len(snap.interfaces) == 1
        assert snap.interfaces[0].interface == "Wi-Fi"

    def test_restore_snapshot(self):
        snap = DNSSnapshot(
            interfaces=[
                InterfaceDNS("Wi-Fi", ["8.8.8.8"], []),
                InterfaceDNS("Ethernet", [], []),
            ],
            resolv_conf="nameserver 8.8.8.8\n",
        )
        calls = []
        with patch("dns._run", side_effect=lambda cmd, **kw: calls.append(cmd)):
            with patch("dns._write_resolv_conf") as mock_write:
                restore_snapshot(snap, flush=False)
        # Verify setdnsservers was called for both interfaces
        set_calls = [c for c in calls if "-setdnsservers" in c]
        assert len(set_calls) == 2
        mock_write.assert_called_once_with("nameserver 8.8.8.8\n")

    def test_restore_snapshot_no_resolv_conf(self):
        snap = DNSSnapshot(interfaces=[], resolv_conf=None)
        with patch("dns._write_resolv_conf") as mock_write:
            restore_snapshot(snap, flush=False)
        mock_write.assert_not_called()

    def test_take_snapshot_skips_error_interfaces(self):
        def fake_run(cmd, check=True):
            if "-listallnetworkservices" in cmd:
                return _completed("Wi-Fi\nBadIface\n")
            if "-getdnsservers" in cmd:
                if "Wi-Fi" in cmd:
                    return _completed("1.1.1.1\n")
                raise RuntimeError("networksetup failed")
            return _completed("")

        with patch("dns._run", side_effect=fake_run):
            snap = take_snapshot()
        # Only Wi-Fi should survive
        assert len(snap.interfaces) == 1


# ---------------------------------------------------------------------------
# DNSLeakProtection
# ---------------------------------------------------------------------------


class TestDNSLeakProtection:
    def _make(
        self,
        servers: Optional[List[str]] = None,
        interfaces: Optional[List[str]] = None,
    ) -> DNSLeakProtection:
        return DNSLeakProtection(
            vpn_dns_servers=servers or ["10.8.0.1"],
            interfaces=interfaces or ["Wi-Fi"],
            update_resolv_conf=False,
        )

    def _patch_run(self, calls_out: Optional[list] = None):
        """Return a patch that records _run calls and returns empty output."""

        def fake(cmd, **kw):
            if calls_out is not None:
                calls_out.append(cmd)
            return _completed("")

        return patch("dns._run", side_effect=fake)

    # ---- constructor validation ----

    def test_rejects_empty_servers(self):
        with pytest.raises(ValueError):
            DNSLeakProtection(vpn_dns_servers=[])

    def test_rejects_invalid_server(self):
        with pytest.raises(ValueError):
            DNSLeakProtection(vpn_dns_servers=["not.an.ip"])

    # ---- start / stop lifecycle ----

    def test_start_sets_active(self):
        prot = self._make()
        with self._patch_run():
            with patch("dns._flush_dns_cache"):
                prot.start()
        assert prot.active is True
        # cleanup
        with self._patch_run():
            with patch("dns._flush_dns_cache"):
                prot.stop()

    def test_stop_clears_active(self):
        prot = self._make()
        with self._patch_run():
            with patch("dns._flush_dns_cache"):
                prot.start()
                prot.stop()
        assert prot.active is False

    def test_double_start_raises(self):
        prot = self._make()
        with self._patch_run():
            with patch("dns._flush_dns_cache"):
                prot.start()
                with pytest.raises(RuntimeError):
                    prot.start()
                prot.stop()

    def test_stop_without_start_raises(self):
        prot = self._make()
        with pytest.raises(RuntimeError):
            prot.stop()

    # ---- context manager ----

    def test_context_manager(self):
        prot = self._make()
        with self._patch_run():
            with patch("dns._flush_dns_cache"):
                with prot:
                    assert prot.active is True
        assert prot.active is False

    def test_context_manager_stops_on_exception(self):
        prot = self._make()
        with self._patch_run():
            with patch("dns._flush_dns_cache"):
                try:
                    with prot:
                        raise ValueError("oops")
                except ValueError:
                    pass
        assert prot.active is False

    # ---- update_servers ----

    def test_update_servers_while_active(self):
        prot = self._make()
        applied: List[List[str]] = []

        def fake_run(cmd, **kw):
            if "-setdnsservers" in cmd:
                applied.append(cmd)
            return _completed("")

        with patch("dns._run", side_effect=fake_run):
            with patch("dns._flush_dns_cache"):
                prot.start()
                prot.update_servers(["10.8.0.2"])
                assert prot.dns_servers == ["10.8.0.2"]
                prot.stop()

        # After update_servers, 10.8.0.2 should appear in one of the set calls
        assert any("10.8.0.2" in item for cmd in applied for item in cmd)

    def test_update_servers_while_inactive(self):
        prot = self._make()
        prot.update_servers(["10.8.0.3"])
        assert prot.dns_servers == ["10.8.0.3"]

    def test_update_rejects_invalid(self):
        prot = self._make()
        with pytest.raises(ValueError):
            prot.update_servers(["bad"])

    def test_update_rejects_empty(self):
        prot = self._make()
        with pytest.raises(ValueError):
            prot.update_servers([])

    # ---- snapshot save/restore flow ----

    def test_start_saves_snapshot_and_applies_vpn_dns(self):
        set_calls: List[List[str]] = []

        def fake_run(cmd, **kw):
            if "-setdnsservers" in cmd:
                set_calls.append(cmd)
            return _completed("1.1.1.1\n" if "-getdnsservers" in cmd else "")

        prot = self._make(servers=["10.8.0.1"], interfaces=["Wi-Fi"])
        with patch("dns._run", side_effect=fake_run):
            with patch("dns._flush_dns_cache"):
                prot.start()
                # Snapshot should have been taken (old DNS = 1.1.1.1)
                assert prot._snapshot is not None
                assert prot._snapshot.interfaces[0].servers == ["1.1.1.1"]
                prot.stop()

        # setdnsservers called with VPN server during start
        assert any("10.8.0.1" in c for c in set_calls[0])

    def test_stop_restores_original_dns(self):
        set_calls: List[List[str]] = []

        def fake_run(cmd, **kw):
            if "-setdnsservers" in cmd:
                set_calls.append(cmd)
            return _completed("1.1.1.1\n" if "-getdnsservers" in cmd else "")

        prot = self._make(servers=["10.8.0.1"], interfaces=["Wi-Fi"])
        with patch("dns._run", side_effect=fake_run):
            with patch("dns._flush_dns_cache"):
                prot.start()
                prot.stop()

        # Last setdnsservers call should restore original 1.1.1.1
        assert any("1.1.1.1" in c for c in set_calls[-1])

    # ---- thread safety ----

    def test_thread_safe_start_stop(self):
        prot = self._make()
        errors: List[Exception] = []

        def fake_run(cmd, **kw):
            return _completed("1.1.1.1\n" if "-getdnsservers" in cmd else "")

        with patch("dns._run", side_effect=fake_run):
            with patch("dns._flush_dns_cache"):
                prot.start()

                def stopper():
                    try:
                        prot.stop()
                    except Exception as exc:
                        errors.append(exc)

                threads = [threading.Thread(target=stopper) for _ in range(5)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()

        # Exactly one stop should succeed; others should raise RuntimeError
        runtime_errors = [e for e in errors if isinstance(e, RuntimeError)]
        assert len(runtime_errors) == 4
        assert prot.active is False


# ---------------------------------------------------------------------------
# dns_protection_for_vpn factory
# ---------------------------------------------------------------------------


class TestDnsProtectionFactory:
    def test_uses_gateway_as_primary(self):
        prot = dns_protection_for_vpn("10.8.0.1")
        assert prot.dns_servers[0] == "10.8.0.1"

    def test_extra_servers_appended(self):
        prot = dns_protection_for_vpn("10.8.0.1", extra_servers=["1.1.1.1"])
        assert prot.dns_servers == ["10.8.0.1", "1.1.1.1"]

    def test_invalid_gateway_raises(self):
        with pytest.raises(ValueError):
            dns_protection_for_vpn("not.an.ip")

    def test_returns_dnsleak_instance(self):
        prot = dns_protection_for_vpn("10.8.0.1")
        assert isinstance(prot, DNSLeakProtection)

    def test_search_domains_passed(self):
        prot = dns_protection_for_vpn("10.8.0.1", search_domains=["local"])
        assert prot._search_domains == ["local"]
