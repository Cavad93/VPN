"""
test_split_tunnel.py — Unit tests for split_tunnel.py.

All subprocess calls (route, pgrep, lsof, osascript) are mocked so the
tests run without root access or a real network.
"""

from __future__ import annotations

import ipaddress
import subprocess
import threading
import time
import types
from typing import Dict, List, Set
from unittest.mock import MagicMock, call, patch

import pytest

from split_tunnel import (
    AppRule,
    SplitTunnel,
    SplitTunnelConfig,
    SplitTunnelMode,
    _PrefixIndex,
    _ProcessMonitor,
    _RouteManager,
    _get_default_gateway,
    create_split_tunnel,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

GATEWAY = "192.168.1.1"
INTERFACE = "en0"


def _completed(stdout="", stderr="", returncode=0) -> subprocess.CompletedProcess:
    r = subprocess.CompletedProcess(args=[], returncode=returncode)
    r.stdout = stdout
    r.stderr = stderr
    return r


# ---------------------------------------------------------------------------
# _PrefixIndex
# ---------------------------------------------------------------------------


class TestPrefixIndex:
    def test_contains_exact_host(self):
        idx = _PrefixIndex(["10.0.0.0/8"])
        assert idx.contains("10.1.2.3")

    def test_not_contains(self):
        idx = _PrefixIndex(["10.0.0.0/8"])
        assert not idx.contains("172.16.0.1")

    def test_multiple_subnets(self):
        idx = _PrefixIndex(["10.0.0.0/8", "192.168.0.0/16"])
        assert idx.contains("192.168.5.5")
        assert idx.contains("10.255.255.255")
        assert not idx.contains("172.16.1.1")

    def test_add_subnet(self):
        idx = _PrefixIndex([])
        assert not idx.contains("8.8.8.8")
        idx.add("8.8.0.0/16")
        assert idx.contains("8.8.8.8")

    def test_invalid_subnet_ignored(self):
        # Should not raise
        idx = _PrefixIndex(["not-a-subnet", "10.0.0.0/8"])
        assert idx.contains("10.0.0.1")

    def test_empty_index(self):
        idx = _PrefixIndex([])
        assert not idx.contains("1.2.3.4")

    def test_host_subnet(self):
        idx = _PrefixIndex(["1.2.3.4/32"])
        assert idx.contains("1.2.3.4")
        assert not idx.contains("1.2.3.5")

    def test_invalid_ip_returns_false(self):
        idx = _PrefixIndex(["10.0.0.0/8"])
        assert not idx.contains("not-an-ip")


# ---------------------------------------------------------------------------
# _RouteManager
# ---------------------------------------------------------------------------


class TestRouteManager:
    def _mgr(self):
        return _RouteManager(GATEWAY, INTERFACE)

    @patch("split_tunnel._run")
    def test_add_bypass_host_calls_route(self, mock_run):
        mock_run.return_value = _completed()
        mgr = self._mgr()
        assert mgr.add_bypass_host("1.2.3.4")
        cmd = mock_run.call_args[0][0]
        assert "route" in cmd and "add" in cmd and "1.2.3.4" in cmd

    @patch("split_tunnel._run")
    def test_add_bypass_host_idempotent(self, mock_run):
        mock_run.return_value = _completed()
        mgr = self._mgr()
        mgr.add_bypass_host("1.2.3.4")
        mgr.add_bypass_host("1.2.3.4")
        # Second call should short-circuit — only one real route command.
        assert mock_run.call_count == 1

    @patch("split_tunnel._run")
    def test_add_bypass_host_file_exists_ok(self, mock_run):
        mock_run.return_value = _completed(stderr="File exists", returncode=1)
        mgr = self._mgr()
        assert mgr.add_bypass_host("1.2.3.4")
        assert "1.2.3.4" in mgr.managed_routes

    @patch("split_tunnel._run")
    def test_add_bypass_subnet(self, mock_run):
        mock_run.return_value = _completed()
        mgr = self._mgr()
        assert mgr.add_bypass_subnet("192.168.0.0/16")
        assert "192.168.0.0/16" in mgr.managed_routes

    @patch("split_tunnel._run")
    def test_add_bypass_subnet_idempotent(self, mock_run):
        mock_run.return_value = _completed()
        mgr = self._mgr()
        mgr.add_bypass_subnet("10.0.0.0/8")
        mgr.add_bypass_subnet("10.0.0.0/8")
        assert mock_run.call_count == 1

    @patch("split_tunnel._run")
    def test_remove_host(self, mock_run):
        mock_run.return_value = _completed()
        mgr = self._mgr()
        mgr.add_bypass_host("5.5.5.5")
        mgr.remove_host("5.5.5.5")
        assert "5.5.5.5" not in mgr.managed_routes

    @patch("split_tunnel._run")
    def test_remove_host_not_managed_noop(self, mock_run):
        mock_run.return_value = _completed()
        mgr = self._mgr()
        # Should not raise even if IP was never added.
        mgr.remove_host("9.9.9.9")

    @patch("split_tunnel._run")
    def test_remove_all(self, mock_run):
        mock_run.return_value = _completed()
        mgr = self._mgr()
        mgr.add_bypass_host("1.1.1.1")
        mgr.add_bypass_subnet("10.0.0.0/8")
        mgr.remove_all()
        assert len(mgr.managed_routes) == 0

    @patch("split_tunnel._run")
    def test_managed_routes_property(self, mock_run):
        mock_run.return_value = _completed()
        mgr = self._mgr()
        mgr.add_bypass_host("2.2.2.2")
        mgr.add_bypass_host("3.3.3.3")
        assert mgr.managed_routes == {"2.2.2.2", "3.3.3.3"}

    @patch("split_tunnel._run")
    def test_route_failure_returns_false(self, mock_run):
        mock_run.return_value = _completed(stderr="some error", returncode=1)
        mgr = self._mgr()
        # "File exists" is NOT in stderr here, so it should fail.
        result = mgr.add_bypass_host("4.4.4.4")
        assert not result
        assert "4.4.4.4" not in mgr.managed_routes


# ---------------------------------------------------------------------------
# _ProcessMonitor
# ---------------------------------------------------------------------------

LSOF_OUTPUT = """\
COMMAND   PID  USER   FD   TYPE  DEVICE SIZE/OFF NODE NAME
Safari  12345  user   14u  IPv4  0x1234      0t0  TCP 192.168.1.5:54321->93.184.216.34:443 (ESTABLISHED)
Safari  12345  user   15u  IPv4  0x1235      0t0  TCP 192.168.1.5:54322->8.8.8.8:443 (ESTABLISHED)
Safari  12345  user   16u  IPv4  0x1236      0t0  TCP 127.0.0.1:54323->127.0.0.1:8080 (ESTABLISHED)
"""


class TestProcessMonitor:
    @patch("split_tunnel._run")
    def test_pgrep_returns_pids(self, mock_run):
        mock_run.return_value = _completed(stdout="123\n456\n")
        mon = _ProcessMonitor()
        pids = mon._pgrep("Safari")
        assert set(pids) == {123, 456}

    @patch("split_tunnel._run")
    def test_pgrep_empty(self, mock_run):
        mock_run.return_value = _completed(stdout="", returncode=1)
        mon = _ProcessMonitor()
        assert mon._pgrep("NonExistentApp") == []

    @patch("split_tunnel._run")
    def test_lsof_ips_parses_correctly(self, mock_run):
        mock_run.return_value = _completed(stdout=LSOF_OUTPUT)
        mon = _ProcessMonitor()
        ips = mon._lsof_ips([12345])
        # loopback should be excluded, remote IPs included
        assert "93.184.216.34" in ips
        assert "8.8.8.8" in ips
        assert "127.0.0.1" not in ips

    @patch("split_tunnel._run")
    def test_lsof_empty_pids(self, mock_run):
        mon = _ProcessMonitor()
        ips = mon._lsof_ips([])
        assert ips == set()
        mock_run.assert_not_called()

    @patch("split_tunnel._run")
    def test_connection_ips_pid_cache_hit(self, mock_run):
        """Second call with same PIDs returns cached IPs without running lsof."""
        pgrep_out = _completed(stdout="999\n")
        lsof_out = _completed(stdout=LSOF_OUTPUT)
        # First call: pgrep + lsof; second call: pgrep only (cache hit).
        mock_run.side_effect = [pgrep_out, lsof_out, pgrep_out]

        mon = _ProcessMonitor()
        rule = AppRule(process_name="Safari")

        ips1, changed1 = mon.connection_ips(rule)
        ips2, changed2 = mon.connection_ips(rule)

        assert changed1 is True
        assert changed2 is False  # PID set same → cache hit
        assert ips1 == ips2

    @patch("split_tunnel._run")
    def test_connection_ips_pid_change_triggers_lsof(self, mock_run):
        """When PIDs change, lsof is re-run."""
        pgrep1 = _completed(stdout="1\n")
        lsof1 = _completed(stdout=LSOF_OUTPUT)
        pgrep2 = _completed(stdout="2\n")  # Different PID
        lsof2 = _completed(stdout="")       # Empty for pid 2
        mock_run.side_effect = [pgrep1, lsof1, pgrep2, lsof2]

        mon = _ProcessMonitor()
        rule = AppRule(process_name="Safari")

        _, c1 = mon.connection_ips(rule)
        _, c2 = mon.connection_ips(rule)

        assert c1 is True
        assert c2 is True  # PID changed → lsof re-run

    @patch("split_tunnel._run")
    def test_connection_ips_app_not_running(self, mock_run):
        mock_run.return_value = _completed(stdout="", returncode=1)
        mon = _ProcessMonitor()
        rule = AppRule(process_name="NonExistent")
        ips, changed = mon.connection_ips(rule)
        assert ips == set()
        assert changed is True


# ---------------------------------------------------------------------------
# _get_default_gateway
# ---------------------------------------------------------------------------


NETSTAT_OUTPUT = """\
Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            192.168.1.1        UGScg           en0
127.0.0.1          127.0.0.1          UH              lo0
"""


class TestGetDefaultGateway:
    @patch("split_tunnel._run")
    def test_parses_gateway(self, mock_run):
        mock_run.return_value = _completed(stdout=NETSTAT_OUTPUT)
        gw, iface = _get_default_gateway()
        assert gw == "192.168.1.1"
        assert iface == "en0"

    @patch("split_tunnel._run")
    def test_fallback_on_error(self, mock_run):
        mock_run.side_effect = Exception("fail")
        gw, iface = _get_default_gateway()
        assert gw  # Should return some default
        assert iface


# ---------------------------------------------------------------------------
# SplitTunnel — lifecycle and static routes
# ---------------------------------------------------------------------------


class TestSplitTunnelLifecycle:
    def _st(self, **kw):
        """Build a SplitTunnel with mocked gateway and no real routes."""
        config = SplitTunnelConfig(**kw)
        return SplitTunnel(config, "utun5", GATEWAY, INTERFACE)

    @patch("split_tunnel._run")
    def test_start_stop(self, mock_run):
        mock_run.return_value = _completed()
        st = self._st()
        st.start()
        assert st._started
        st.stop()
        assert not st._started

    @patch("split_tunnel._run")
    def test_double_start_idempotent(self, mock_run):
        mock_run.return_value = _completed()
        st = self._st()
        st.start()
        st.start()
        st.stop()

    @patch("split_tunnel._run")
    def test_stop_without_start(self, mock_run):
        mock_run.return_value = _completed()
        st = self._st()
        st.stop()  # Should not raise

    @patch("split_tunnel._run")
    def test_static_subnets_applied_on_start(self, mock_run):
        mock_run.return_value = _completed()
        st = self._st(bypass_subnets=["10.0.0.0/8", "172.16.0.0/12"])
        st.start()
        st.stop()
        # route add should have been called for each subnet
        calls = [c[0][0] for c in mock_run.call_args_list]
        subnet_adds = [c for c in calls if "add" in c and "-net" in c]
        assert len(subnet_adds) == 2

    @patch("split_tunnel._run")
    def test_stop_removes_all_routes(self, mock_run):
        mock_run.return_value = _completed()
        st = self._st(bypass_subnets=["10.0.0.0/8"])
        st.start()
        assert len(st.managed_routes) > 0
        st.stop()
        assert len(st.managed_routes) == 0


# ---------------------------------------------------------------------------
# SplitTunnel — dynamic app rules
# ---------------------------------------------------------------------------


class TestSplitTunnelAppRules:
    def _st(self, apps=None, **kw):
        config = SplitTunnelConfig(apps=apps or [], **kw)
        return SplitTunnel(config, "utun5", GATEWAY, INTERFACE)

    @patch("split_tunnel._run")
    def test_add_app_rule(self, mock_run):
        mock_run.return_value = _completed()
        st = self._st()
        st.start()
        rule = AppRule(process_name="Sberbank")
        st.add_app(rule)
        assert any(r.process_name == "Sberbank" for r in st._config.apps)
        st.stop()

    @patch("split_tunnel._run")
    def test_remove_app_rule(self, mock_run):
        mock_run.return_value = _completed()
        rule = AppRule(process_name="Banking")
        st = self._st(apps=[rule])
        st.start()
        st.remove_app(process_name="Banking")
        assert not any(r.process_name == "Banking" for r in st._config.apps)
        st.stop()

    @patch("split_tunnel._run")
    def test_add_bypass_subnet_dynamic(self, mock_run):
        mock_run.return_value = _completed()
        st = self._st()
        st.start()
        st.add_bypass_subnet("172.16.0.0/12")
        assert "172.16.0.0/12" in st.managed_routes
        st.stop()

    @patch("split_tunnel._run")
    def test_scan_adds_bypass_routes(self, mock_run):
        """Simulate one scan cycle: pgrep finds PID → lsof finds IP → route added."""
        # Sequence: route add (start), pgrep, lsof, route add (for discovered IP)
        mock_run.side_effect = [
            _completed(),                        # No static subnets
            _completed(stdout="555\n"),          # pgrep
            _completed(stdout=(
                "Proc  555 user  1u IPv4 0x0 0t0 TCP "
                "1.2.3.4:5678->5.6.7.8:443 (ESTABLISHED)\n"
            )),                                  # lsof
            _completed(),                        # route add for 5.6.7.8
        ]
        rule = AppRule(process_name="TestApp")
        st = self._st(apps=[rule], scan_interval=0.05)
        st.start()
        time.sleep(0.2)
        st.stop()
        # route add for 5.6.7.8 should have been called
        all_calls = [" ".join(c[0][0]) for c in mock_run.call_args_list]
        assert any("5.6.7.8" in c for c in all_calls)

    @patch("split_tunnel._run")
    def test_static_subnet_skips_host_route(self, mock_run):
        """If IP is covered by a static subnet, no host route is added."""
        # pgrep finds a PID, lsof returns an IP in 10.0.0.0/8
        mock_run.side_effect = [
            _completed(),                        # subnet route add on start
            _completed(stdout="42\n"),           # pgrep
            _completed(stdout=(
                "Proc  42 user 1u IPv4 0x0 0t0 TCP "
                "10.1.2.3:9999->10.5.5.5:80 (ESTABLISHED)\n"
            )),                                  # lsof
        ]
        rule = AppRule(process_name="LAN_App")
        st = self._st(apps=[rule], bypass_subnets=["10.0.0.0/8"], scan_interval=0.05)
        st.start()
        time.sleep(0.2)
        st.stop()
        # 10.5.5.5 is in 10.0.0.0/8 — should NOT add a host route for it
        all_calls = [" ".join(c[0][0]) for c in mock_run.call_args_list]
        host_adds = [c for c in all_calls if "add" in c and "-host" in c and "10.5.5.5" in c]
        assert len(host_adds) == 0

    @patch("split_tunnel._run")
    def test_ip_not_removed_when_still_needed_by_other_app(self, mock_run):
        """Route is kept when another app still uses the same IP."""
        mock_run.return_value = _completed()
        rule_a = AppRule(process_name="AppA")
        rule_b = AppRule(process_name="AppB")
        st = self._st(apps=[rule_a, rule_b])
        st.start()

        # Manually inject shared IP into both app route sets
        shared_ip = "9.9.9.9"
        with st._lock:
            st._app_routes["AppA"] = {shared_ip}
            st._app_routes["AppB"] = {shared_ip}

        # Removing AppA should NOT call route delete because AppB still needs it
        st.remove_app(process_name="AppA")
        delete_calls = [
            " ".join(c[0][0]) for c in mock_run.call_args_list
            if "delete" in c[0][0]
        ]
        assert not any(shared_ip in c for c in delete_calls)
        st.stop()


# ---------------------------------------------------------------------------
# SplitTunnel — properties
# ---------------------------------------------------------------------------


class TestSplitTunnelProperties:
    @patch("split_tunnel._run")
    def test_original_gateway_property(self, mock_run):
        mock_run.return_value = _completed()
        st = SplitTunnel(SplitTunnelConfig(), "utun5", "10.0.0.1", "eth0")
        assert st.original_gateway == "10.0.0.1"

    @patch("split_tunnel._run")
    def test_config_property(self, mock_run):
        config = SplitTunnelConfig(mode=SplitTunnelMode.INCLUDE)
        st = SplitTunnel(config, "utun5", GATEWAY, INTERFACE)
        assert st.config.mode == SplitTunnelMode.INCLUDE


# ---------------------------------------------------------------------------
# create_split_tunnel factory
# ---------------------------------------------------------------------------


class TestCreateSplitTunnel:
    @patch("split_tunnel._run")
    def test_factory_exclude(self, mock_run):
        mock_run.return_value = _completed()
        st = create_split_tunnel(
            mode="exclude",
            apps=["Tinkoff", "Sberbank"],
            bypass_subnets=["192.168.0.0/16"],
            vpn_interface="utun3",
            original_gateway=GATEWAY,
            original_interface=INTERFACE,
        )
        assert st._config.mode == SplitTunnelMode.EXCLUDE
        assert len(st._config.apps) == 2
        assert st._config.apps[0].process_name == "Tinkoff"
        assert len(st._config.bypass_subnets) == 1

    @patch("split_tunnel._run")
    def test_factory_include(self, mock_run):
        mock_run.return_value = _completed()
        st = create_split_tunnel(mode="include", original_gateway=GATEWAY)
        assert st._config.mode == SplitTunnelMode.INCLUDE

    @patch("split_tunnel._run")
    def test_factory_no_apps(self, mock_run):
        mock_run.return_value = _completed()
        st = create_split_tunnel(original_gateway=GATEWAY)
        assert st._config.apps == []

    @patch("split_tunnel._run")
    def test_factory_starts_and_stops(self, mock_run):
        mock_run.return_value = _completed()
        st = create_split_tunnel(
            bypass_subnets=["10.0.0.0/8"],
            original_gateway=GATEWAY,
            original_interface=INTERFACE,
        )
        st.start()
        st.stop()
        assert not st._started


# ---------------------------------------------------------------------------
# Thread safety sanity check
# ---------------------------------------------------------------------------


class TestThreadSafety:
    @patch("split_tunnel._run")
    def test_concurrent_add_remove_app(self, mock_run):
        """Concurrent modifications must not raise."""
        mock_run.return_value = _completed()
        st = SplitTunnel(SplitTunnelConfig(), "utun5", GATEWAY, INTERFACE)
        st.start()

        errors: List[Exception] = []

        def adder():
            for i in range(20):
                try:
                    st.add_app(AppRule(process_name=f"app{i}"))
                except Exception as e:
                    errors.append(e)

        def remover():
            for i in range(20):
                try:
                    st.remove_app(process_name=f"app{i}")
                except Exception as e:
                    errors.append(e)

        threads = [threading.Thread(target=adder), threading.Thread(target=remover)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        st.stop()

        assert errors == [], f"Thread safety errors: {errors}"

    @patch("split_tunnel._run")
    def test_concurrent_add_bypass_subnet(self, mock_run):
        mock_run.return_value = _completed()
        st = SplitTunnel(SplitTunnelConfig(), "utun5", GATEWAY, INTERFACE)
        st.start()

        errors: List[Exception] = []

        def adder(subnet):
            try:
                st.add_bypass_subnet(subnet)
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=adder, args=(f"10.{i}.0.0/24",))
            for i in range(10)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        st.stop()

        assert errors == []


# ---------------------------------------------------------------------------
# SplitTunnelMode enum
# ---------------------------------------------------------------------------


class TestSplitTunnelMode:
    def test_exclude_value(self):
        assert SplitTunnelMode.EXCLUDE.value == "exclude"

    def test_include_value(self):
        assert SplitTunnelMode.INCLUDE.value == "include"

    def test_from_string(self):
        assert SplitTunnelMode("exclude") == SplitTunnelMode.EXCLUDE
        assert SplitTunnelMode("include") == SplitTunnelMode.INCLUDE


# ---------------------------------------------------------------------------
# AppRule defaults
# ---------------------------------------------------------------------------


class TestAppRule:
    def test_defaults(self):
        rule = AppRule()
        assert rule.process_name == ""
        assert rule.bundle_id == ""

    def test_process_name_only(self):
        rule = AppRule(process_name="Safari")
        assert rule.process_name == "Safari"
        assert rule.bundle_id == ""

    def test_bundle_id_only(self):
        rule = AppRule(bundle_id="com.apple.Safari")
        assert rule.bundle_id == "com.apple.Safari"


# ---------------------------------------------------------------------------
# SplitTunnelConfig defaults
# ---------------------------------------------------------------------------


class TestSplitTunnelConfig:
    def test_defaults(self):
        cfg = SplitTunnelConfig()
        assert cfg.mode == SplitTunnelMode.EXCLUDE
        assert cfg.apps == []
        assert cfg.bypass_subnets == []
        assert cfg.scan_interval == 5.0

    def test_custom_values(self):
        cfg = SplitTunnelConfig(
            mode=SplitTunnelMode.INCLUDE,
            apps=[AppRule(process_name="X")],
            bypass_subnets=["10.0.0.0/8"],
            scan_interval=2.5,
        )
        assert cfg.mode == SplitTunnelMode.INCLUDE
        assert len(cfg.apps) == 1
        assert "10.0.0.0/8" in cfg.bypass_subnets
        assert cfg.scan_interval == 2.5
