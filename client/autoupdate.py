"""
autoupdate.py — CavadVPN automatic client update system.

Checks for new versions against a configured update URL, downloads
and installs updates silently without blocking the VPN data path.

Performance: runs entirely in a background daemon thread; zero impact
on VPN throughput. Streaming download uses 64 KB chunks to match the
server-side streamReadBufPool size, avoiding excess GC pressure.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Callable, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

__all__ = [
    "UpdateInfo",
    "UpdateConfig",
    "UpdateState",
    "AutoUpdater",
    "create_auto_updater",
]

CURRENT_VERSION = "1.0.0"
DEFAULT_CHECK_INTERVAL_S: float = 3600.0  # 1 hour
DEFAULT_TIMEOUT_S: float = 30.0
# Matches server-side streamReadBufPool — avoids GC pressure on large downloads.
_DOWNLOAD_CHUNK_SIZE = 65536


class UpdateState(Enum):
    """Lifecycle states of the auto-updater."""

    IDLE = auto()
    CHECKING = auto()
    DOWNLOADING = auto()
    INSTALLING = auto()
    RESTART_PENDING = auto()
    UP_TO_DATE = auto()
    ERROR = auto()


@dataclass
class UpdateInfo:
    """Metadata for an available update returned by the version endpoint."""

    version: str
    download_url: str
    sha256: str
    release_notes: str = ""
    min_os_version: str = ""

    def is_newer_than(self, current: str) -> bool:
        """Return True when *self.version* is semantically newer than *current*."""

        def _parts(v: str) -> tuple[int, ...]:
            try:
                return tuple(int(x) for x in v.strip().lstrip("v").split("."))
            except ValueError:
                return (0,)

        return _parts(self.version) > _parts(current)


@dataclass
class UpdateConfig:
    """Configuration for AutoUpdater."""

    update_url: str
    """URL of a JSON endpoint returning the latest client version info."""

    current_version: str = CURRENT_VERSION
    check_interval_s: float = DEFAULT_CHECK_INTERVAL_S
    timeout_s: float = DEFAULT_TIMEOUT_S
    install_dir: Optional[Path] = None
    """Directory containing Python client files. Defaults to directory of this module."""

    auto_install: bool = True
    """If True, download and install updates automatically."""

    on_update_available: Optional[Callable[["UpdateInfo"], None]] = None
    on_update_installed: Optional[Callable[["UpdateInfo"], None]] = None
    on_error: Optional[Callable[[Exception], None]] = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


class _VersionParser:
    """Parses version JSON from the update endpoint.

    Expected format::

        {
          "version":       "1.2.3",
          "download_url":  "https://...",
          "sha256":        "abcdef...",
          "release_notes": "...",         (optional)
          "min_os_version": "12.0"        (optional)
        }
    """

    @staticmethod
    def parse(data: bytes) -> UpdateInfo:
        obj = json.loads(data)
        return UpdateInfo(
            version=str(obj["version"]),
            download_url=str(obj["download_url"]),
            sha256=str(obj["sha256"]),
            release_notes=str(obj.get("release_notes", "")),
            min_os_version=str(obj.get("min_os_version", "")),
        )


class _Downloader:
    """Streams a file from a URL to disk, verifying SHA-256 on the fly."""

    def download(
        self,
        url: str,
        dest: Path,
        expected_sha256: str,
        timeout: float = DEFAULT_TIMEOUT_S,
        current_version: str = CURRENT_VERSION,
    ) -> None:
        """Download *url* → *dest*, verify hash; raise ValueError on mismatch."""
        req = Request(url, headers={"User-Agent": f"CavadVPN/{current_version}"})
        hasher = hashlib.sha256()

        with urlopen(req, timeout=timeout) as resp, open(dest, "wb") as fh:
            while True:
                # Streaming: never holds the whole file in memory.
                chunk = resp.read(_DOWNLOAD_CHUNK_SIZE)
                if not chunk:
                    break
                fh.write(chunk)
                hasher.update(chunk)

        actual = hasher.hexdigest().lower()
        if actual != expected_sha256.lower():
            dest.unlink(missing_ok=True)
            raise ValueError(
                f"SHA256 mismatch: expected {expected_sha256!r}, got {actual!r}"
            )


class _Installer:
    """Applies a downloaded update package to the install directory."""

    def install(self, package_path: Path, install_dir: Path) -> None:
        """Route to the correct install strategy based on file extension."""
        name = package_path.name.lower()
        if name.endswith(".pkg"):
            self._install_pkg(package_path)
        elif name.endswith(".zip"):
            self._install_zip(package_path, install_dir)
        else:
            raise ValueError(f"Unsupported update package: {package_path.name}")

    # ── macOS .pkg via system installer ──────────────────────────────────────

    def _install_pkg(self, pkg_path: Path) -> None:
        if platform.system() != "Darwin":
            raise RuntimeError(".pkg install is only supported on macOS")
        subprocess.run(
            ["sudo", "installer", "-pkg", str(pkg_path), "-target", "/"],
            check=True,
            capture_output=True,
        )

    # ── ZIP with Python source files ─────────────────────────────────────────

    def _install_zip(self, zip_path: Path, install_dir: Path) -> None:
        import zipfile

        backup_dir = install_dir.parent / f"{install_dir.name}.bak"

        with tempfile.TemporaryDirectory() as tmpdir:
            with zipfile.ZipFile(zip_path) as zf:
                zf.extractall(tmpdir)

            extracted = list(Path(tmpdir).iterdir())
            src = extracted[0] if (len(extracted) == 1 and extracted[0].is_dir()) else Path(tmpdir)

            # Backup existing installation before replacing.
            if install_dir.exists() and not backup_dir.exists():
                shutil.copytree(install_dir, backup_dir)

            for item in src.iterdir():
                dest = install_dir / item.name
                if item.is_dir():
                    if dest.exists():
                        shutil.rmtree(dest)
                    shutil.copytree(item, dest)
                else:
                    shutil.copy2(item, dest)

        # Remove backup only after successful install.
        if backup_dir.exists():
            shutil.rmtree(backup_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Public class
# ---------------------------------------------------------------------------


class AutoUpdater:
    """
    Background auto-updater for the CavadVPN client.

    Starts a single daemon thread that:
      1. Waits 60 s after start (avoids competing with VPN startup).
      2. Fetches version JSON from *config.update_url*.
      3. If a newer version is found, downloads and installs it.
      4. Sleeps for *config.check_interval_s*, then repeats.

    The VPN data path is never touched — all network/disk I/O happens
    exclusively inside the background daemon thread.

    Example::

        updater = create_auto_updater("https://myserver/api/v1/client/version")
        updater.start()
        # ... VPN runs normally ...
        updater.stop()
    """

    def __init__(self, config: UpdateConfig) -> None:
        self._cfg = config
        self._state = UpdateState.IDLE
        self._state_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_error: Optional[Exception] = None
        self._last_checked_at: float = 0.0
        self._pending_update: Optional[UpdateInfo] = None
        self._downloader = _Downloader()
        self._installer = _Installer()
        self._log = logging.getLogger(__name__)

        self._install_dir: Path = (
            Path(config.install_dir) if config.install_dir is not None else Path(__file__).parent
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the background update-checker daemon thread."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="cavadvpn-autoupdate",
            daemon=True,
        )
        self._thread.start()
        self._log.debug("auto-updater started (interval=%ss)", self._cfg.check_interval_s)

    def stop(self) -> None:
        """Signal the background thread to exit and wait up to 5 s."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    @property
    def state(self) -> UpdateState:
        with self._state_lock:
            return self._state

    @property
    def last_error(self) -> Optional[Exception]:
        return self._last_error

    @property
    def pending_update(self) -> Optional[UpdateInfo]:
        return self._pending_update

    @property
    def last_checked_at(self) -> float:
        """Monotonic timestamp of the last completed version check."""
        return self._last_checked_at

    def check_now(self) -> Optional[UpdateInfo]:
        """
        Synchronously check for an update (blocks the caller).

        Returns UpdateInfo if a newer version is available, None otherwise.
        Suitable for manual "Check for updates" button in UI.
        """
        return self._check_for_update()

    def install_pending(self) -> bool:
        """Install the pending update (if any). Returns True on success."""
        if self._pending_update is None:
            return False
        return self._do_install(self._pending_update)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _set_state(self, state: UpdateState) -> None:
        with self._state_lock:
            self._state = state

    def _fire(self, cb: Optional[Callable], *args) -> None:  # type: ignore[type-arg]
        if cb is not None:
            try:
                cb(*args)
            except Exception:
                pass

    def _run_loop(self) -> None:
        # Delay first check so it doesn't compete with VPN tunnel setup.
        if self._stop_event.wait(timeout=60):
            return

        while not self._stop_event.is_set():
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
                self._log.warning("auto-update cycle error: %s", exc)
                self._fire(self._cfg.on_error, exc)

            # Interruptible sleep — stop() wakes us immediately.
            self._stop_event.wait(timeout=self._cfg.check_interval_s)

    def _check_for_update(self) -> Optional[UpdateInfo]:
        """Fetch version JSON; return UpdateInfo if newer, else None."""
        self._set_state(UpdateState.CHECKING)
        try:
            req = Request(
                self._cfg.update_url,
                headers={
                    "User-Agent": f"CavadVPN/{self._cfg.current_version}",
                    "Accept": "application/json",
                },
            )
            with urlopen(req, timeout=self._cfg.timeout_s) as resp:
                # Cap at 64 KB — version JSON is tiny.
                data = resp.read(65536)

            info = _VersionParser.parse(data)

            if info.is_newer_than(self._cfg.current_version):
                self._log.info(
                    "update available: %s → %s", self._cfg.current_version, info.version
                )
                return info

            self._set_state(UpdateState.UP_TO_DATE)
            return None

        except (URLError, HTTPError) as exc:
            # Network unavailable — treat as transient; retry next interval.
            self._set_state(UpdateState.IDLE)
            self._log.debug("version check network error (will retry): %s", exc)
            return None
        finally:
            self._last_checked_at = time.monotonic()

    def _do_install(self, info: UpdateInfo) -> bool:
        """Download and install *info*. Returns True on success."""
        self._set_state(UpdateState.DOWNLOADING)

        with tempfile.TemporaryDirectory() as tmpdir:
            url_path = info.download_url.split("?")[0]
            filename = url_path.rsplit("/", 1)[-1] or "update.zip"
            dest = Path(tmpdir) / filename

            try:
                self._downloader.download(
                    info.download_url,
                    dest,
                    info.sha256,
                    # Allow 10× the normal timeout for the actual download.
                    timeout=self._cfg.timeout_s * 10,
                    current_version=self._cfg.current_version,
                )
            except Exception as exc:
                self._last_error = exc
                self._set_state(UpdateState.ERROR)
                self._log.error("update download failed: %s", exc)
                self._fire(self._cfg.on_error, exc)
                return False

            self._set_state(UpdateState.INSTALLING)
            try:
                self._installer.install(dest, self._install_dir)
            except Exception as exc:
                self._last_error = exc
                self._set_state(UpdateState.ERROR)
                self._log.error("update install failed: %s", exc)
                self._fire(self._cfg.on_error, exc)
                return False

        self._pending_update = None
        self._set_state(UpdateState.RESTART_PENDING)
        self._log.info("update %s installed — restart to activate", info.version)
        self._fire(self._cfg.on_update_installed, info)
        return True


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create_auto_updater(
    update_url: str,
    current_version: str = CURRENT_VERSION,
    check_interval_s: float = DEFAULT_CHECK_INTERVAL_S,
    auto_install: bool = True,
    on_update_available: Optional[Callable[[UpdateInfo], None]] = None,
    on_update_installed: Optional[Callable[[UpdateInfo], None]] = None,
    on_error: Optional[Callable[[Exception], None]] = None,
    install_dir: Optional[Path] = None,
) -> AutoUpdater:
    """Create an AutoUpdater with the given settings."""
    cfg = UpdateConfig(
        update_url=update_url,
        current_version=current_version,
        check_interval_s=check_interval_s,
        auto_install=auto_install,
        on_update_available=on_update_available,
        on_update_installed=on_update_installed,
        on_error=on_error,
        install_dir=install_dir,
    )
    return AutoUpdater(cfg)
