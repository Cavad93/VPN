"""
test_killswitch.py — Unit tests for killswitch.py.

All pfctl / subprocess calls are mocked so tests run without root or macOS.
"""

from __future__ import annotations

import subprocess
from typing import Optional
from unittest.mock import MagicMock, call, patch

import pytest

import killswitch as ks_mod
from killswitch import (
    KillSwitch,
    _ANCHOR,
    _RULES_TEMPLATE,
    _anchor_exists,
    _enable_pf,
    _flush_anchor,
    _get_anchor_rules,
    _get_pf_enabled,
    _load_anchor_rules,
    create_kill_switch,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_completed(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    r = MagicMock(spec=subprocess.CompletedProcess)
    r.returncode = returncode
    r.stdout = stdout
    r.stderr = stderr
    return r


# ---------------------------------------------------------------------------
# _run helper
# ---------------------------------------------------------------------------


class TestRun:
    def test_success(self):
        with patch("killswitch.subprocess.run", return_value=_make_completed()) as mock_run:
            result = ks_mod._run(["pfctl", "-e"])
            mock_run.assert_called_once()
            assert result.returncode == 0

    def test_failure_raises(self):
        exc = subprocess.CalledProcessError(1, "pfctl", stderr="no permission")
        with patch("killswitch.subprocess.run", side_effect=exc):
            with pytest.raises(subprocess.CalledProcessError):
                ks_mod._run(["pfctl", "-e"])

    def test_check_false_no_raise(self):
        with patch("killswitch.subprocess.run", return_value=_make_completed(returncode=1)) as mock_run:
            result = ks_mod._run(["pfctl", "-e"], check=False)
            assert result.returncode == 1

    def test_input_forwarded(self):
        with patch("killswitch.subprocess.run", return_value=_make_completed()) as mock_run:
            ks_mod._run(["pfctl", "-f", "-"], input="pass all\n")
            _, kwargs = mock_run.call_args
            assert kwargs["input"] == "pass all\n"


# ---------------------------------------------------------------------------
# Low-level pfctl helpers
# ---------------------------------------------------------------------------


class TestPfctlHelpers:
    def test_anchor_exists_true(self):
        result = _make_completed(stdout="block drop all\n")
        with patch("killswitch._run", return_value=result):
            assert _anchor_exists() is True

    def test_anchor_exists_false_empty_stdout(self):
        result = _make_completed(stdout="")
        with patch("killswitch._run", return_value=result):
            assert _anchor_exists() is False

    def test_anchor_exists_false_nonzero(self):
        result = _make_completed(returncode=1, stdout="")
        with patch("killswitch._run", return_value=result):
            assert _anchor_exists() is False

    def test_load_anchor_rules_calls_pfctl(self):
        mock_file = MagicMock()
        mock_file.__enter__ = lambda s: s
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_file.name = "/tmp/fake.pf"

        with patch("killswitch._run") as mock_run, \
             patch("killswitch.tempfile.NamedTemporaryFile", return_value=mock_file), \
             patch("killswitch.os.unlink"):

            _load_anchor_rules("pass all\n")

            mock_run.assert_called_once_with(
                ["pfctl", "-a", _ANCHOR, "-f", "/tmp/fake.pf"]
            )

    def test_flush_anchor(self):
        with patch("killswitch._run") as mock_run:
            _flush_anchor()
            mock_run.assert_called_once_with(
                ["pfctl", "-a", _ANCHOR, "-F", "rules"], check=False
            )

    def test_enable_pf_when_disabled(self):
        disabled = _make_completed(stdout="Status: Disabled")
        with patch("killswitch._run", side_effect=[disabled, _make_completed()]) as mock_run:
            _enable_pf()
            assert mock_run.call_count == 2
            assert mock_run.call_args_list[1] == call(["pfctl", "-e"], check=False)

    def test_enable_pf_already_enabled(self):
        enabled = _make_completed(stdout="Status: Enabled")
        with patch("killswitch._run", return_value=enabled) as mock_run:
            _enable_pf()
            # Only the status check should have been called
            mock_run.assert_called_once_with(["pfctl", "-s", "info"], check=False)

    def test_get_pf_enabled_true(self):
        with patch("killswitch._run", return_value=_make_completed(stdout="Status: Enabled\n")):
            assert _get_pf_enabled() is True

    def test_get_pf_enabled_false(self):
        with patch("killswitch._run", return_value=_make_completed(stdout="Status: Disabled\n")):
            assert _get_pf_enabled() is False

    def test_get_pf_enabled_error(self):
        with patch("killswitch._run", return_value=_make_completed(returncode=1)):
            assert _get_pf_enabled() is False

    def test_get_anchor_rules_success(self):
        rules = "block drop all\n"
        with patch("killswitch._run", return_value=_make_completed(stdout=rules)):
            assert _get_anchor_rules() == rules

    def test_get_anchor_rules_error(self):
        with patch("killswitch._run", return_value=_make_completed(returncode=1, stdout="")):
            assert _get_anchor_rules() == ""


# ---------------------------------------------------------------------------
# KillSwitch class
# ---------------------------------------------------------------------------


def _patch_ks():
    """Return a context-manager that patches all pfctl calls.

    _get_pf_enabled returns True so stop() does NOT call pfctl -d,
    keeping tests hermetic (no subprocess spawned).
    """
    return patch.multiple(
        "killswitch",
        _get_pf_enabled=MagicMock(return_value=True),
        _enable_pf=MagicMock(),
        _load_anchor_rules=MagicMock(),
        _flush_anchor=MagicMock(),
        _get_anchor_rules=MagicMock(return_value="block drop all\n"),
    )


class TestKillSwitchInit:
    def test_initial_state(self):
        ks = KillSwitch()
        assert ks.active is False
        assert ks.vpn_interface is None
        assert ks.server_ip is None


class TestKillSwitchStart:
    def test_start_sets_active(self):
        with _patch_ks():
            ks = KillSwitch()
            ks.start("utun3", "1.2.3.4")
            assert ks.active is True
            assert ks.vpn_interface == "utun3"
            assert ks.server_ip == "1.2.3.4"

    def test_start_calls_enable_pf(self):
        with _patch_ks() as mocks:
            ks = KillSwitch()
            ks.start("utun3", "1.2.3.4")
            ks_mod._enable_pf.assert_called_once()

    def test_start_loads_rules(self):
        with _patch_ks():
            ks = KillSwitch()
            ks.start("utun3", "1.2.3.4")
            rules_arg = ks_mod._load_anchor_rules.call_args[0][0]
            assert "utun3" in rules_arg
            assert "1.2.3.4" in rules_arg
            assert "block drop all" in rules_arg

    def test_start_twice_raises(self):
        with _patch_ks():
            ks = KillSwitch()
            ks.start("utun3", "1.2.3.4")
            with pytest.raises(RuntimeError, match="already active"):
                ks.start("utun3", "1.2.3.4")

    def test_rules_contain_loopback(self):
        with _patch_ks():
            ks = KillSwitch()
            ks.start("utun3", "1.2.3.4")
            rules_arg = ks_mod._load_anchor_rules.call_args[0][0]
            assert "lo0" in rules_arg

    def test_rules_contain_dhcp(self):
        with _patch_ks():
            ks = KillSwitch()
            ks.start("utun3", "1.2.3.4")
            rules_arg = ks_mod._load_anchor_rules.call_args[0][0]
            assert "port 67" in rules_arg
            assert "port 68" in rules_arg

    def test_pf_was_enabled_remembered_true(self):
        with patch("killswitch._get_pf_enabled", return_value=True), \
             patch("killswitch._enable_pf"), \
             patch("killswitch._load_anchor_rules"), \
             patch("killswitch._flush_anchor"):
            ks = KillSwitch()
            ks.start("utun3", "1.2.3.4")
            assert ks._pf_was_enabled is True

    def test_pf_was_enabled_remembered_false(self):
        with patch("killswitch._get_pf_enabled", return_value=False), \
             patch("killswitch._enable_pf"), \
             patch("killswitch._load_anchor_rules"), \
             patch("killswitch._flush_anchor"):
            ks = KillSwitch()
            ks.start("utun3", "1.2.3.4")
            assert ks._pf_was_enabled is False


class TestKillSwitchStop:
    def test_stop_clears_active(self):
        with _patch_ks():
            ks = KillSwitch()
            ks.start("utun3", "1.2.3.4")
            ks.stop()
            assert ks.active is False

    def test_stop_clears_fields(self):
        with _patch_ks():
            ks = KillSwitch()
            ks.start("utun3", "1.2.3.4")
            ks.stop()
            assert ks.vpn_interface is None
            assert ks.server_ip is None

    def test_stop_flushes_anchor(self):
        with _patch_ks():
            ks = KillSwitch()
            ks.start("utun3", "1.2.3.4")
            ks.stop()
            ks_mod._flush_anchor.assert_called_once()

    def test_stop_disables_pf_if_was_disabled(self):
        with patch("killswitch._flush_anchor"), \
             patch("killswitch._run") as mock_run:
            ks = KillSwitch()
            ks._pf_was_enabled = False
            ks._active = True
            ks.stop()
            mock_run.assert_called_with(["pfctl", "-d"], check=False)

    def test_stop_keeps_pf_if_was_enabled(self):
        with patch("killswitch._flush_anchor"), \
             patch("killswitch._run") as mock_run:
            ks = KillSwitch()
            ks._pf_was_enabled = True
            ks._active = True
            ks.stop()
            # pfctl -d must NOT be called
            for c in mock_run.call_args_list:
                assert c != call(["pfctl", "-d"], check=False)

    def test_stop_noop_when_not_active(self):
        with _patch_ks():
            ks = KillSwitch()
            ks.stop()  # must not raise
            assert ks.active is False

    def test_stop_noop_does_not_flush(self):
        with _patch_ks():
            ks = KillSwitch()
            ks.stop()
            ks_mod._flush_anchor.assert_not_called()


class TestKillSwitchUpdate:
    def test_update_new_interface(self):
        with _patch_ks():
            ks = KillSwitch()
            ks.start("utun3", "1.2.3.4")
            ks_mod._load_anchor_rules.reset_mock()
            ks.update(vpn_interface="utun4")
            assert ks.vpn_interface == "utun4"
            rules_arg = ks_mod._load_anchor_rules.call_args[0][0]
            assert "utun4" in rules_arg

    def test_update_new_server_ip(self):
        with _patch_ks():
            ks = KillSwitch()
            ks.start("utun3", "1.2.3.4")
            ks_mod._load_anchor_rules.reset_mock()
            ks.update(server_ip="5.6.7.8")
            assert ks.server_ip == "5.6.7.8"
            rules_arg = ks_mod._load_anchor_rules.call_args[0][0]
            assert "5.6.7.8" in rules_arg

    def test_update_both(self):
        with _patch_ks():
            ks = KillSwitch()
            ks.start("utun3", "1.2.3.4")
            ks_mod._load_anchor_rules.reset_mock()
            ks.update(vpn_interface="utun5", server_ip="9.9.9.9")
            assert ks.vpn_interface == "utun5"
            assert ks.server_ip == "9.9.9.9"

    def test_update_none_keeps_values(self):
        with _patch_ks():
            ks = KillSwitch()
            ks.start("utun3", "1.2.3.4")
            ks_mod._load_anchor_rules.reset_mock()
            ks.update()
            assert ks.vpn_interface == "utun3"
            assert ks.server_ip == "1.2.3.4"

    def test_update_raises_when_inactive(self):
        ks = KillSwitch()
        with pytest.raises(RuntimeError, match="not active"):
            ks.update(vpn_interface="utun3")


class TestKillSwitchGetCurrentRules:
    def test_returns_empty_when_inactive(self):
        ks = KillSwitch()
        assert ks.get_current_rules() == ""

    def test_returns_rules_when_active(self):
        with _patch_ks():
            ks = KillSwitch()
            ks.start("utun3", "1.2.3.4")
            rules = ks.get_current_rules()
            assert rules == "block drop all\n"


class TestKillSwitchContextManager:
    def test_context_manager_calls_stop(self):
        with _patch_ks():
            with KillSwitch() as ks:
                ks.start("utun3", "1.2.3.4")
                assert ks.active is True
            assert ks.active is False

    def test_context_manager_stop_on_exception(self):
        with _patch_ks():
            try:
                with KillSwitch() as ks:
                    ks.start("utun3", "1.2.3.4")
                    raise ValueError("simulated error")
            except ValueError:
                pass
            assert ks.active is False

    def test_context_manager_without_start(self):
        # Should not raise even if start() was never called
        with KillSwitch():
            pass


# ---------------------------------------------------------------------------
# Rules template
# ---------------------------------------------------------------------------


class TestRulesTemplate:
    def test_template_contains_server_ip(self):
        rules = _RULES_TEMPLATE.format(vpn_iface="utun3", server_ip="1.2.3.4")
        assert "1.2.3.4" in rules

    def test_template_contains_iface(self):
        rules = _RULES_TEMPLATE.format(vpn_iface="utun3", server_ip="1.2.3.4")
        assert "utun3" in rules

    def test_template_has_block_rule(self):
        rules = _RULES_TEMPLATE.format(vpn_iface="utun3", server_ip="1.2.3.4")
        assert "block drop all" in rules

    def test_template_has_loopback(self):
        rules = _RULES_TEMPLATE.format(vpn_iface="utun3", server_ip="1.2.3.4")
        assert "lo0" in rules

    def test_template_has_dhcp(self):
        rules = _RULES_TEMPLATE.format(vpn_iface="utun3", server_ip="1.2.3.4")
        assert "port 67" in rules
        assert "port 68" in rules


# ---------------------------------------------------------------------------
# Factory function
# ---------------------------------------------------------------------------


class TestCreateKillSwitch:
    def test_returns_killswitch_instance(self):
        result = create_kill_switch()
        assert isinstance(result, KillSwitch)

    def test_returns_new_instance_each_time(self):
        ks1 = create_kill_switch()
        ks2 = create_kill_switch()
        assert ks1 is not ks2
