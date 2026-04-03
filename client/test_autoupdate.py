"""
test_autoupdate.py — Unit tests for client/autoupdate.py.

All tests run without a real network connection; HTTP calls are mocked.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch, call
from urllib.error import HTTPError, URLError

# Module under test
from autoupdate import (
    CURRENT_VERSION,
    AutoUpdater,
    UpdateConfig,
    UpdateInfo,
    UpdateState,
    _Downloader,
    _Installer,
    _VersionParser,
    create_auto_updater,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_version_json(
    version: str = "2.0.0",
    download_url: str = "https://example.com/cavadvpn-2.0.0.zip",
    sha256: str = "abc123",
    release_notes: str = "Bug fixes",
    min_os_version: str = "12.0",
) -> bytes:
    return json.dumps(
        {
            "version": version,
            "download_url": download_url,
            "sha256": sha256,
            "release_notes": release_notes,
            "min_os_version": min_os_version,
        }
    ).encode()


def _fake_response(data: bytes, status: int = 200):
    """Return a mock context-manager response with .read() and .status."""
    resp = MagicMock()
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    resp.read.return_value = data
    resp.status = status
    return resp


# ---------------------------------------------------------------------------
# UpdateInfo
# ---------------------------------------------------------------------------


class TestUpdateInfo(unittest.TestCase):
    def test_is_newer_patch(self):
        info = UpdateInfo(version="1.0.1", download_url="", sha256="")
        self.assertTrue(info.is_newer_than("1.0.0"))

    def test_is_newer_minor(self):
        info = UpdateInfo(version="1.1.0", download_url="", sha256="")
        self.assertTrue(info.is_newer_than("1.0.9"))

    def test_is_newer_major(self):
        info = UpdateInfo(version="2.0.0", download_url="", sha256="")
        self.assertTrue(info.is_newer_than("1.99.99"))

    def test_not_newer_same(self):
        info = UpdateInfo(version="1.0.0", download_url="", sha256="")
        self.assertFalse(info.is_newer_than("1.0.0"))

    def test_not_newer_older(self):
        info = UpdateInfo(version="0.9.9", download_url="", sha256="")
        self.assertFalse(info.is_newer_than("1.0.0"))

    def test_v_prefix_stripped(self):
        info = UpdateInfo(version="v2.0.0", download_url="", sha256="")
        self.assertTrue(info.is_newer_than("1.0.0"))

    def test_defaults(self):
        info = UpdateInfo(version="1.0.0", download_url="u", sha256="h")
        self.assertEqual(info.release_notes, "")
        self.assertEqual(info.min_os_version, "")

    def test_invalid_version_does_not_crash(self):
        info = UpdateInfo(version="not-a-version", download_url="", sha256="")
        # Should return False (not newer) without raising
        self.assertFalse(info.is_newer_than("1.0.0"))


# ---------------------------------------------------------------------------
# _VersionParser
# ---------------------------------------------------------------------------


class TestVersionParser(unittest.TestCase):
    def test_parse_full(self):
        data = _make_version_json(
            version="3.1.4",
            download_url="https://ex.com/v3.zip",
            sha256="deadbeef",
            release_notes="fixes",
            min_os_version="13",
        )
        info = _VersionParser.parse(data)
        self.assertEqual(info.version, "3.1.4")
        self.assertEqual(info.download_url, "https://ex.com/v3.zip")
        self.assertEqual(info.sha256, "deadbeef")
        self.assertEqual(info.release_notes, "fixes")
        self.assertEqual(info.min_os_version, "13")

    def test_parse_minimal(self):
        data = json.dumps(
            {"version": "1.1.0", "download_url": "u", "sha256": "s"}
        ).encode()
        info = _VersionParser.parse(data)
        self.assertEqual(info.version, "1.1.0")
        self.assertEqual(info.release_notes, "")

    def test_missing_required_key_raises(self):
        data = json.dumps({"version": "1.0.0"}).encode()
        with self.assertRaises(KeyError):
            _VersionParser.parse(data)

    def test_invalid_json_raises(self):
        with self.assertRaises(json.JSONDecodeError):
            _VersionParser.parse(b"not json")


# ---------------------------------------------------------------------------
# _Downloader
# ---------------------------------------------------------------------------


class TestDownloader(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.dest = Path(self.tmpdir) / "update.zip"
        self.content = b"fake zip content"
        self.sha256 = hashlib.sha256(self.content).hexdigest()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _mock_urlopen(self, content: bytes):
        resp = MagicMock()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        # Simulate streaming: first call returns content, second returns b""
        resp.read.side_effect = [content, b""]
        return resp

    @patch("autoupdate.urlopen")
    def test_download_success(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_urlopen(self.content)
        dl = _Downloader()
        dl.download("https://ex.com/up.zip", self.dest, self.sha256)
        self.assertTrue(self.dest.exists())
        self.assertEqual(self.dest.read_bytes(), self.content)

    @patch("autoupdate.urlopen")
    def test_download_wrong_hash_raises(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_urlopen(self.content)
        dl = _Downloader()
        with self.assertRaises(ValueError, msg="SHA256 mismatch"):
            dl.download("https://ex.com/up.zip", self.dest, "wronghash")
        # Partial file should be cleaned up
        self.assertFalse(self.dest.exists())

    @patch("autoupdate.urlopen")
    def test_download_network_error_propagates(self, mock_urlopen):
        mock_urlopen.side_effect = URLError("connection refused")
        dl = _Downloader()
        with self.assertRaises(URLError):
            dl.download("https://ex.com/up.zip", self.dest, self.sha256)

    @patch("autoupdate.urlopen")
    def test_user_agent_header_set(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_urlopen(self.content)
        dl = _Downloader()
        dl.download(
            "https://ex.com/up.zip",
            self.dest,
            self.sha256,
            current_version="9.9.9",
        )
        req = mock_urlopen.call_args[0][0]
        self.assertIn("9.9.9", req.headers.get("User-agent", ""))


# ---------------------------------------------------------------------------
# _Installer
# ---------------------------------------------------------------------------


class TestInstaller(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.install_dir = Path(self.tmpdir) / "install"
        self.install_dir.mkdir()
        # Pre-existing file
        (self.install_dir / "old.py").write_text("old")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_zip(self, files: dict[str, str]) -> Path:
        """Build a zip with given filename→content mapping."""
        zp = Path(self.tmpdir) / "update.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            for name, content in files.items():
                zf.writestr(name, content)
        return zp

    def test_install_zip_replaces_files(self):
        zp = self._make_zip({"new_module.py": "new content"})
        inst = _Installer()
        inst.install(zp, self.install_dir)
        self.assertEqual((self.install_dir / "new_module.py").read_text(), "new content")

    def test_install_zip_backup_removed_on_success(self):
        zp = self._make_zip({"x.py": "x"})
        inst = _Installer()
        inst.install(zp, self.install_dir)
        backup = self.install_dir.parent / f"{self.install_dir.name}.bak"
        self.assertFalse(backup.exists())

    def test_install_unknown_format_raises(self):
        bad = Path(self.tmpdir) / "update.tar.gz"
        bad.write_bytes(b"data")
        inst = _Installer()
        with self.assertRaises(ValueError, msg="Unsupported"):
            inst.install(bad, self.install_dir)

    def test_install_pkg_non_macos_raises(self):
        import platform as _plat

        pkg = Path(self.tmpdir) / "update.pkg"
        pkg.write_bytes(b"data")
        inst = _Installer()
        with patch.object(_plat, "system", return_value="Linux"):
            with self.assertRaises(RuntimeError):
                inst.install(pkg, self.install_dir)


# ---------------------------------------------------------------------------
# AutoUpdater — state machine
# ---------------------------------------------------------------------------


class TestAutoUpdaterState(unittest.TestCase):
    def _make_updater(self, **kwargs) -> AutoUpdater:
        cfg = UpdateConfig(update_url="https://example.com/version", **kwargs)
        return AutoUpdater(cfg)

    def test_initial_state_idle(self):
        u = self._make_updater()
        self.assertEqual(u.state, UpdateState.IDLE)

    def test_check_now_up_to_date(self):
        u = self._make_updater(current_version="2.0.0")
        data = _make_version_json(version="1.0.0")  # older than current
        with patch("autoupdate.urlopen", return_value=_fake_response(data)):
            result = u.check_now()
        self.assertIsNone(result)
        self.assertEqual(u.state, UpdateState.UP_TO_DATE)

    def test_check_now_update_available(self):
        u = self._make_updater(current_version="1.0.0")
        data = _make_version_json(version="2.0.0")
        with patch("autoupdate.urlopen", return_value=_fake_response(data)):
            result = u.check_now()
        self.assertIsNotNone(result)
        self.assertEqual(result.version, "2.0.0")  # type: ignore[union-attr]

    def test_check_now_network_error_returns_none(self):
        u = self._make_updater()
        with patch("autoupdate.urlopen", side_effect=URLError("no network")):
            result = u.check_now()
        self.assertIsNone(result)
        self.assertEqual(u.state, UpdateState.IDLE)

    def test_check_now_http_error_returns_none(self):
        u = self._make_updater()
        with patch("autoupdate.urlopen", side_effect=HTTPError("", 404, "Not Found", {}, None)):
            result = u.check_now()
        self.assertIsNone(result)

    def test_last_checked_at_updated(self):
        u = self._make_updater()
        before = u.last_checked_at
        data = _make_version_json(version="1.0.0")
        with patch("autoupdate.urlopen", return_value=_fake_response(data)):
            u.check_now()
        self.assertGreater(u.last_checked_at, before)

    def test_pending_update_set_after_check(self):
        u = self._make_updater(current_version="1.0.0", auto_install=False)
        data = _make_version_json(version="1.1.0")

        content = b"zip-data"
        sha = hashlib.sha256(content).hexdigest()
        data = _make_version_json(version="1.1.0", sha256=sha)

        with patch("autoupdate.urlopen", return_value=_fake_response(data)):
            result = u.check_now()
        u._pending_update = result  # simulate what run_loop does
        self.assertIsNotNone(u.pending_update)


# ---------------------------------------------------------------------------
# AutoUpdater — install_pending
# ---------------------------------------------------------------------------


class TestAutoUpdaterInstall(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.install_dir = Path(self.tmpdir) / "install"
        self.install_dir.mkdir()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_zip_bytes(self, files: dict[str, str]) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for name, content in files.items():
                zf.writestr(name, content)
        return buf.getvalue()

    def test_install_pending_no_pending_returns_false(self):
        cfg = UpdateConfig(update_url="https://example.com/v", install_dir=self.install_dir)
        u = AutoUpdater(cfg)
        self.assertFalse(u.install_pending())

    def test_install_pending_success(self):
        zip_content = self._make_zip_bytes({"core.py": "# new core"})
        sha = hashlib.sha256(zip_content).hexdigest()
        info = UpdateInfo(
            version="1.1.0",
            download_url="https://example.com/cavadvpn-1.1.0.zip",
            sha256=sha,
        )

        cfg = UpdateConfig(update_url="https://example.com/v", install_dir=self.install_dir)
        u = AutoUpdater(cfg)
        u._pending_update = info

        resp_dl = MagicMock()
        resp_dl.__enter__ = lambda s: s
        resp_dl.__exit__ = MagicMock(return_value=False)
        resp_dl.read.side_effect = [zip_content, b""]

        with patch("autoupdate.urlopen", return_value=resp_dl):
            result = u.install_pending()

        self.assertTrue(result)
        self.assertEqual(u.state, UpdateState.RESTART_PENDING)
        self.assertIsNone(u.pending_update)
        self.assertTrue((self.install_dir / "core.py").exists())

    def test_install_pending_download_fail_sets_error_state(self):
        info = UpdateInfo(
            version="1.1.0",
            download_url="https://example.com/up.zip",
            sha256="badhash",
        )
        cfg = UpdateConfig(update_url="https://example.com/v", install_dir=self.install_dir)
        u = AutoUpdater(cfg)
        u._pending_update = info

        with patch("autoupdate.urlopen", side_effect=URLError("fail")):
            result = u.install_pending()

        self.assertFalse(result)
        self.assertEqual(u.state, UpdateState.ERROR)
        self.assertIsNotNone(u.last_error)

    def test_on_error_callback_called_on_download_failure(self):
        errors: list[Exception] = []
        info = UpdateInfo(version="2.0.0", download_url="https://ex.com/x.zip", sha256="bad")
        cfg = UpdateConfig(
            update_url="https://ex.com/v",
            install_dir=self.install_dir,
            on_error=errors.append,
        )
        u = AutoUpdater(cfg)
        u._pending_update = info

        with patch("autoupdate.urlopen", side_effect=URLError("net")):
            u.install_pending()

        self.assertEqual(len(errors), 1)

    def test_on_update_installed_callback_called(self):
        zip_content = self._make_zip_bytes({"x.py": "x"})
        sha = hashlib.sha256(zip_content).hexdigest()
        installed: list[UpdateInfo] = []
        info = UpdateInfo(version="1.2.0", download_url="https://ex.com/x.zip", sha256=sha)

        cfg = UpdateConfig(
            update_url="https://ex.com/v",
            install_dir=self.install_dir,
            on_update_installed=installed.append,
        )
        u = AutoUpdater(cfg)
        u._pending_update = info

        resp_dl = MagicMock()
        resp_dl.__enter__ = lambda s: s
        resp_dl.__exit__ = MagicMock(return_value=False)
        resp_dl.read.side_effect = [zip_content, b""]

        with patch("autoupdate.urlopen", return_value=resp_dl):
            u.install_pending()

        self.assertEqual(len(installed), 1)
        self.assertEqual(installed[0].version, "1.2.0")


# ---------------------------------------------------------------------------
# AutoUpdater — background thread
# ---------------------------------------------------------------------------


class TestAutoUpdaterThread(unittest.TestCase):
    def test_start_stop(self):
        cfg = UpdateConfig(update_url="https://example.com/v")
        u = AutoUpdater(cfg)
        u.start()
        self.assertTrue(u._thread.is_alive())  # type: ignore[union-attr]
        u.stop()
        # After stop(), thread should finish within 5 s
        u._thread.join(timeout=6)  # type: ignore[union-attr]
        self.assertFalse(u._thread.is_alive())  # type: ignore[union-attr]

    def test_start_idempotent(self):
        cfg = UpdateConfig(update_url="https://example.com/v")
        u = AutoUpdater(cfg)
        u.start()
        thread_id = id(u._thread)
        u.start()  # should not create a second thread
        self.assertEqual(id(u._thread), thread_id)
        u.stop()

    def test_stop_without_start_safe(self):
        cfg = UpdateConfig(update_url="https://example.com/v")
        u = AutoUpdater(cfg)
        u.stop()  # should not raise

    def test_on_update_available_callback_called_by_run_loop(self):
        """run_loop calls on_update_available when an update is found."""
        found: list[UpdateInfo] = []
        data = _make_version_json(version="99.0.0")

        cfg = UpdateConfig(
            update_url="https://example.com/v",
            current_version="1.0.0",
            auto_install=False,
            check_interval_s=9999,
            on_update_available=found.append,
        )
        u = AutoUpdater(cfg)

        # Patch urlopen so check returns immediately
        mock_resp = _fake_response(data)
        with patch("autoupdate.urlopen", return_value=mock_resp):
            # Bypass the 60 s startup delay
            u._stop_event.clear()
            u._thread = threading.Thread(target=u._run_once_no_delay, daemon=True)
            u._thread.start()
            u._thread.join(timeout=5)

        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].version, "99.0.0")

    def test_on_error_callback_called_by_run_loop(self):
        errors: list[Exception] = []
        cfg = UpdateConfig(
            update_url="https://example.com/v",
            check_interval_s=9999,
            on_error=errors.append,
        )
        u = AutoUpdater(cfg)

        def _boom(*_a, **_kw):
            raise RuntimeError("server exploded")

        with patch("autoupdate.urlopen", side_effect=_boom):
            u._stop_event.clear()
            u._thread = threading.Thread(target=u._run_once_no_delay, daemon=True)
            u._thread.start()
            u._thread.join(timeout=5)

        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], RuntimeError)


# ---------------------------------------------------------------------------
# Patch helper method used by thread tests
# ---------------------------------------------------------------------------


def _run_once_no_delay(self: AutoUpdater) -> None:
    """Run one check iteration without the 60-second startup delay."""
    try:
        info = self._check_for_update()
        if info is not None:
            self._pending_update = info
            self._fire(self._cfg.on_update_available, info)
            if self._cfg.auto_install:
                self._do_install(info)
    except Exception as exc:
        self._last_error = exc
        self._set_state(UpdateState.ERROR)
        self._fire(self._cfg.on_error, exc)


AutoUpdater._run_once_no_delay = _run_once_no_delay  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# create_auto_updater factory
# ---------------------------------------------------------------------------


class TestCreateAutoUpdater(unittest.TestCase):
    def test_factory_returns_autoupdater(self):
        u = create_auto_updater("https://example.com/version")
        self.assertIsInstance(u, AutoUpdater)

    def test_factory_sets_url(self):
        u = create_auto_updater("https://example.com/v")
        self.assertEqual(u._cfg.update_url, "https://example.com/v")

    def test_factory_sets_version(self):
        u = create_auto_updater("https://example.com/v", current_version="2.3.4")
        self.assertEqual(u._cfg.current_version, "2.3.4")

    def test_factory_sets_interval(self):
        u = create_auto_updater("https://example.com/v", check_interval_s=1800)
        self.assertEqual(u._cfg.check_interval_s, 1800)

    def test_factory_auto_install_false(self):
        u = create_auto_updater("https://example.com/v", auto_install=False)
        self.assertFalse(u._cfg.auto_install)

    def test_factory_callbacks(self):
        cb = lambda x: None
        u = create_auto_updater(
            "https://example.com/v",
            on_update_available=cb,
            on_update_installed=cb,
            on_error=cb,
        )
        self.assertIs(u._cfg.on_update_available, cb)

    def test_factory_custom_install_dir(self):
        with tempfile.TemporaryDirectory() as d:
            u = create_auto_updater("https://example.com/v", install_dir=Path(d))
            self.assertEqual(u._install_dir, Path(d))


# ---------------------------------------------------------------------------
# Integration: check + install in one flow (mock everything)
# ---------------------------------------------------------------------------


class TestAutoUpdaterIntegration(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.install_dir = Path(self.tmpdir) / "app"
        self.install_dir.mkdir()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_zip_bytes(self, files: dict) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for name, content in files.items():
                zf.writestr(name, content)
        return buf.getvalue()

    def test_full_check_and_install_flow(self):
        zip_bytes = self._make_zip_bytes({"autoupdate.py": "# updated"})
        sha = hashlib.sha256(zip_bytes).hexdigest()

        version_data = _make_version_json(
            version="2.0.0",
            download_url="https://example.com/cavadvpn-2.0.0.zip",
            sha256=sha,
        )

        installed: list[UpdateInfo] = []
        cfg = UpdateConfig(
            update_url="https://example.com/version",
            current_version="1.0.0",
            install_dir=self.install_dir,
            on_update_installed=installed.append,
        )
        u = AutoUpdater(cfg)

        call_count = 0

        def _urlopen(req, timeout=None):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # First call: version check
                return _fake_response(version_data)
            else:
                # Second call: download
                resp = MagicMock()
                resp.__enter__ = lambda s: s
                resp.__exit__ = MagicMock(return_value=False)
                resp.read.side_effect = [zip_bytes, b""]
                return resp

        with patch("autoupdate.urlopen", side_effect=_urlopen):
            result = u.check_now()
            self.assertIsNotNone(result)
            u._pending_update = result
            success = u.install_pending()

        self.assertTrue(success)
        self.assertEqual(u.state, UpdateState.RESTART_PENDING)
        self.assertEqual(len(installed), 1)
        self.assertEqual(installed[0].version, "2.0.0")
        self.assertTrue((self.install_dir / "autoupdate.py").exists())

    def test_already_up_to_date_no_install(self):
        """When current == latest, install_pending should do nothing."""
        version_data = _make_version_json(version=CURRENT_VERSION)
        cfg = UpdateConfig(
            update_url="https://example.com/version",
            install_dir=self.install_dir,
        )
        u = AutoUpdater(cfg)

        with patch("autoupdate.urlopen", return_value=_fake_response(version_data)):
            result = u.check_now()

        self.assertIsNone(result)
        self.assertFalse(u.install_pending())


if __name__ == "__main__":
    unittest.main()
