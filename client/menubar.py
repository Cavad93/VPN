"""
menubar.py — macOS menu bar VPN application using PyObjC.

Displays a status icon in the macOS menu bar with:
- Connect / Disconnect toggle
- Current connection status
- Real-time traffic statistics (↓ / ↑ bytes, uptime)
- Assigned VPN IP and server address

Usage:
    from menubar import VPNStatusModel, VPNStatus, run_menubar_app

    model = VPNStatusModel()
    run_menubar_app(
        model,
        connect_action=lambda: vpn_client.connect(),
        disconnect_action=lambda: vpn_client.disconnect(),
    )

Requires macOS with PyObjC installed:
    pip install pyobjc-core pyobjc-framework-Cocoa
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional

import structlog

# PyObjC is macOS-only; import guarded so unit tests can run anywhere.
try:
    import AppKit
    import Foundation
    import objc

    _PYOBJC_AVAILABLE = True
except ImportError:  # pragma: no cover – non-macOS CI
    _PYOBJC_AVAILABLE = False

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Domain model (pure Python, no PyObjC dependency)
# ---------------------------------------------------------------------------


class VPNStatus(Enum):
    """VPN connection lifecycle states."""

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTING = "disconnecting"
    ERROR = "error"


@dataclass
class TrafficStats:
    """Real-time traffic counters and connection metadata."""

    bytes_in: int = 0
    bytes_out: int = 0
    connected_since: Optional[float] = None
    server_ip: str = ""
    assigned_ip: str = ""

    # ------------------------------------------------------------------
    # Formatting helpers
    # ------------------------------------------------------------------

    @staticmethod
    def format_bytes(n: int) -> str:
        """Return a human-readable byte count (B / KB / MB / GB / TB)."""
        value = float(n)
        for unit in ("B", "KB", "MB", "GB"):
            if value < 1024.0:
                return f"{value:.1f} {unit}"
            value /= 1024.0
        return f"{value:.1f} TB"

    @property
    def uptime(self) -> str:
        """Return HH:MM:SS (or MM:SS) since connection was established."""
        if self.connected_since is None:
            return ""
        total = int(time.monotonic() - self.connected_since)
        hours, remainder = divmod(total, 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours:
            return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        return f"{minutes:02d}:{seconds:02d}"

    @property
    def ingress_label(self) -> str:
        return f"\u2193 {self.format_bytes(self.bytes_in)}"

    @property
    def egress_label(self) -> str:
        return f"\u2191 {self.format_bytes(self.bytes_out)}"

    def reset(self) -> None:
        """Clear all counters and connection metadata."""
        self.bytes_in = 0
        self.bytes_out = 0
        self.connected_since = None
        self.server_ip = ""
        self.assigned_ip = ""


class VPNStatusModel:
    """
    Thread-safe state model shared between the VPN engine and the UI.

    The UI (VPNMenuBarController) reads this model periodically.
    The VPN engine writes to it via the public mutator methods.
    Registered callbacks are called synchronously on the mutating thread.
    """

    def __init__(self) -> None:
        self._status: VPNStatus = VPNStatus.DISCONNECTED
        self._stats: TrafficStats = TrafficStats()
        self._lock: threading.Lock = threading.Lock()
        self._status_callbacks: list[Callable[[VPNStatus], None]] = []
        self._stats_callbacks: list[Callable[[TrafficStats], None]] = []

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def status(self) -> VPNStatus:
        with self._lock:
            return self._status

    @property
    def stats(self) -> TrafficStats:
        """Return a shallow copy so callers see a stable snapshot."""
        with self._lock:
            s = self._stats
            from dataclasses import replace

            return replace(s)

    # ------------------------------------------------------------------
    # Mutators (called by the VPN engine)
    # ------------------------------------------------------------------

    def set_status(self, status: VPNStatus) -> None:
        """Update connection status and notify callbacks."""
        with self._lock:
            self._status = status
        logger.info("vpn_status_changed", status=status.value)
        for cb in self._status_callbacks:
            try:
                cb(status)
            except Exception:
                logger.exception("status_callback_error")

    def update_traffic(self, bytes_in: int, bytes_out: int) -> None:
        """Update traffic counters (cumulative totals since connection)."""
        with self._lock:
            self._stats.bytes_in = bytes_in
            self._stats.bytes_out = bytes_out
        for cb in self._stats_callbacks:
            try:
                cb(self._stats)
            except Exception:
                logger.exception("stats_callback_error")

    def set_server_info(self, server_ip: str, assigned_ip: str) -> None:
        """Record server and assigned IP once handshake completes."""
        with self._lock:
            self._stats.server_ip = server_ip
            self._stats.assigned_ip = assigned_ip
            self._stats.connected_since = time.monotonic()

    def clear_server_info(self) -> None:
        """Reset all traffic stats when connection drops."""
        with self._lock:
            self._stats.reset()

    # ------------------------------------------------------------------
    # Callback registration
    # ------------------------------------------------------------------

    def on_status_change(self, cb: Callable[[VPNStatus], None]) -> None:
        """Register a callback invoked whenever status changes."""
        self._status_callbacks.append(cb)

    def on_stats_update(self, cb: Callable[[TrafficStats], None]) -> None:
        """Register a callback invoked whenever traffic counters change."""
        self._stats_callbacks.append(cb)

    # ------------------------------------------------------------------
    # UI helpers
    # ------------------------------------------------------------------

    def status_label(self) -> str:
        """Human-readable status string for the menu header."""
        _labels = {
            VPNStatus.DISCONNECTED: "Disconnected",
            VPNStatus.CONNECTING: "Connecting\u2026",
            VPNStatus.CONNECTED: "Connected",
            VPNStatus.DISCONNECTING: "Disconnecting\u2026",
            VPNStatus.ERROR: "Error",
        }
        with self._lock:
            return _labels[self._status]

    def menu_bar_title(self) -> str:
        """
        Short Unicode symbol shown in the macOS menu bar.

        🔒 = connected, ⏳ = connecting/disconnecting, ⚠ = error, 🔓 = off
        """
        with self._lock:
            s = self._status
        if s == VPNStatus.CONNECTED:
            return "\U0001f512"  # 🔒
        if s in (VPNStatus.CONNECTING, VPNStatus.DISCONNECTING):
            return "\u23f3"  # ⏳
        if s == VPNStatus.ERROR:
            return "\u26a0\ufe0f"  # ⚠️
        return "\U0001f513"  # 🔓

    def can_connect(self) -> bool:
        """True when the user may initiate a connection."""
        with self._lock:
            return self._status in (VPNStatus.DISCONNECTED, VPNStatus.ERROR)

    def can_disconnect(self) -> bool:
        """True when the user may disconnect."""
        with self._lock:
            return self._status == VPNStatus.CONNECTED


# ---------------------------------------------------------------------------
# PyObjC-backed UI (only imported / used on macOS with PyObjC)
# ---------------------------------------------------------------------------

if _PYOBJC_AVAILABLE:  # pragma: no cover – exercised in macOS integration tests

    class VPNMenuBarController(AppKit.NSObject):  # type: ignore[misc]
        """
        NSObject subclass that owns the NSStatusItem and its NSMenu.

        Lifecycle
        ---------
        1. Allocate and initialise with ``initWithModel_``.
        2. Call ``setup()`` after the NSApplication has launched.
        3. A repeating 1-second NSTimer drives ``timerFired_`` which refreshes
           the menu title and all statistics labels.
        4. Call ``teardown()`` before quitting to release the status item.
        """

        def initWithModel_(self, model: VPNStatusModel) -> "VPNMenuBarController":
            self = objc.super(VPNMenuBarController, self).init()  # type: ignore[call-arg]
            if self is None:
                return None  # type: ignore[return-value]
            self._model = model
            self._status_item: Optional[AppKit.NSStatusItem] = None
            self._menu: Optional[AppKit.NSMenu] = None
            self._timer: Optional[Foundation.NSTimer] = None
            self._connect_action: Optional[Callable[[], None]] = None
            self._disconnect_action: Optional[Callable[[], None]] = None
            # Retained menu-item references for fast in-place updates
            self._mi_status_header: Optional[AppKit.NSMenuItem] = None
            self._mi_toggle: Optional[AppKit.NSMenuItem] = None
            self._mi_ingress: Optional[AppKit.NSMenuItem] = None
            self._mi_egress: Optional[AppKit.NSMenuItem] = None
            self._mi_uptime: Optional[AppKit.NSMenuItem] = None
            self._mi_server: Optional[AppKit.NSMenuItem] = None
            self._mi_assigned: Optional[AppKit.NSMenuItem] = None
            return self

        # ---- public configuration ----------------------------------------

        @objc.python_method  # type: ignore[misc]
        def set_connect_action(self, action: Callable[[], None]) -> None:
            """Register callable invoked when the user clicks Connect."""
            self._connect_action = action

        @objc.python_method  # type: ignore[misc]
        def set_disconnect_action(self, action: Callable[[], None]) -> None:
            """Register callable invoked when the user clicks Disconnect."""
            self._disconnect_action = action

        # ---- lifecycle -------------------------------------------------------

        @objc.python_method  # type: ignore[misc]
        def setup(self) -> None:
            """
            Create the NSStatusItem and start the refresh timer.

            Must be called on the main thread after NSApplication has launched.
            """
            status_bar = AppKit.NSStatusBar.systemStatusBar()
            self._status_item = status_bar.statusItemWithLength_(
                AppKit.NSVariableStatusItemLength
            )
            self._status_item.setHighlightMode_(True)
            self._update_bar_title()
            self._build_menu()

            # 1-second repeating timer for live stats refresh
            self._timer = (
                Foundation.NSTimer.scheduledTimerWithTimeInterval_target_selector_userInfo_repeats_(
                    1.0,
                    self,
                    objc.selector(self.timerFired_, signature=b"v@:@"),
                    None,
                    True,
                )
            )

        @objc.python_method  # type: ignore[misc]
        def teardown(self) -> None:
            """Invalidate timer and remove status item from the menu bar."""
            if self._timer is not None:
                self._timer.invalidate()
                self._timer = None
            if self._status_item is not None:
                AppKit.NSStatusBar.systemStatusBar().removeStatusItem_(
                    self._status_item
                )
                self._status_item = None

        # ---- NSTimer callback -----------------------------------------------

        def timerFired_(self, timer: Foundation.NSTimer) -> None:  # type: ignore[misc]
            """Refresh menu bar icon and statistics labels (called every second)."""
            self._update_bar_title()
            self._refresh_menu_items()

        # ---- private helpers -------------------------------------------------

        @objc.python_method  # type: ignore[misc]
        def _update_bar_title(self) -> None:
            if self._status_item is not None:
                self._status_item.setTitle_(self._model.menu_bar_title())

        @objc.python_method  # type: ignore[misc]
        def _make_item(
            self, title: str, action=None, key: str = "", enabled: bool = True
        ) -> AppKit.NSMenuItem:
            item = AppKit.NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
                title, action, key
            )
            item.setEnabled_(enabled)
            return item

        @objc.python_method  # type: ignore[misc]
        def _build_menu(self) -> None:
            """Construct the dropdown menu and wire up all menu items."""
            self._menu = AppKit.NSMenu.alloc().init()
            self._menu.setAutoenablesItems_(False)

            # ---- Status header (non-clickable) ----------------------------
            self._mi_status_header = self._make_item(
                self._model.status_label(), enabled=False
            )
            self._menu.addItem_(self._mi_status_header)
            self._menu.addItem_(AppKit.NSMenuItem.separatorItem())

            # ---- Connect / Disconnect toggle ------------------------------
            toggle_sel = objc.selector(self.toggleVPN_, signature=b"v@:@")
            self._mi_toggle = self._make_item("Connect", action=toggle_sel)
            self._mi_toggle.setTarget_(self)
            self._menu.addItem_(self._mi_toggle)
            self._menu.addItem_(AppKit.NSMenuItem.separatorItem())

            # ---- Traffic section -----------------------------------------
            self._menu.addItem_(
                self._make_item("Traffic", enabled=False)
            )
            self._mi_ingress = self._make_item("\u2193 0 B", enabled=False)
            self._menu.addItem_(self._mi_ingress)
            self._mi_egress = self._make_item("\u2191 0 B", enabled=False)
            self._menu.addItem_(self._mi_egress)
            self._mi_uptime = self._make_item("Uptime: \u2014", enabled=False)
            self._menu.addItem_(self._mi_uptime)
            self._menu.addItem_(AppKit.NSMenuItem.separatorItem())

            # ---- Server info --------------------------------------------
            self._mi_server = self._make_item("Server: \u2014", enabled=False)
            self._menu.addItem_(self._mi_server)
            self._mi_assigned = self._make_item("IP: \u2014", enabled=False)
            self._menu.addItem_(self._mi_assigned)
            self._menu.addItem_(AppKit.NSMenuItem.separatorItem())

            # ---- Quit ---------------------------------------------------
            quit_sel = objc.selector(self.quitApp_, signature=b"v@:@")
            quit_item = self._make_item("Quit CavadVPN", action=quit_sel, key="q")
            quit_item.setTarget_(self)
            self._menu.addItem_(quit_item)

            self._status_item.setMenu_(self._menu)  # type: ignore[union-attr]

        @objc.python_method  # type: ignore[misc]
        def _refresh_menu_items(self) -> None:
            """Update all dynamic menu items from the current model state."""
            status = self._model.status
            stats = self._model.stats

            # Status header
            if self._mi_status_header is not None:
                self._mi_status_header.setTitle_(self._model.status_label())

            # Toggle label and enabled state
            if self._mi_toggle is not None:
                if status == VPNStatus.CONNECTED:
                    self._mi_toggle.setTitle_("Disconnect")
                    self._mi_toggle.setEnabled_(True)
                elif status in (VPNStatus.DISCONNECTED, VPNStatus.ERROR):
                    self._mi_toggle.setTitle_("Connect")
                    self._mi_toggle.setEnabled_(True)
                else:
                    self._mi_toggle.setTitle_("Connecting\u2026")
                    self._mi_toggle.setEnabled_(False)

            # Traffic statistics
            if status == VPNStatus.CONNECTED:
                if self._mi_ingress is not None:
                    self._mi_ingress.setTitle_(stats.ingress_label)
                if self._mi_egress is not None:
                    self._mi_egress.setTitle_(stats.egress_label)
                if self._mi_uptime is not None:
                    uptime = stats.uptime or "\u2014"
                    self._mi_uptime.setTitle_(f"Uptime: {uptime}")
                if self._mi_server is not None:
                    srv = stats.server_ip or "\u2014"
                    self._mi_server.setTitle_(f"Server: {srv}")
                if self._mi_assigned is not None:
                    ip = stats.assigned_ip or "\u2014"
                    self._mi_assigned.setTitle_(f"IP: {ip}")
            else:
                for mi, default in [
                    (self._mi_ingress, "\u2193 0 B"),
                    (self._mi_egress, "\u2191 0 B"),
                    (self._mi_uptime, "Uptime: \u2014"),
                    (self._mi_server, "Server: \u2014"),
                    (self._mi_assigned, "IP: \u2014"),
                ]:
                    if mi is not None:
                        mi.setTitle_(default)

        # ---- NSMenuItem actions -------------------------------------------

        def toggleVPN_(self, sender) -> None:  # type: ignore[misc]
            """Connect or disconnect based on current status."""
            if self._model.can_disconnect() and self._disconnect_action:
                threading.Thread(
                    target=self._disconnect_action, daemon=True, name="vpn-disconnect"
                ).start()
            elif self._model.can_connect() and self._connect_action:
                threading.Thread(
                    target=self._connect_action, daemon=True, name="vpn-connect"
                ).start()

        def quitApp_(self, sender) -> None:  # type: ignore[misc]
            """Terminate the application gracefully."""
            self.teardown()
            AppKit.NSApplication.sharedApplication().terminate_(self)

    # -----------------------------------------------------------------------

    class VPNMenuBarAppDelegate(AppKit.NSObject):  # type: ignore[misc]
        """
        NSApplicationDelegate that bridges AppKit lifecycle to our controller.

        Sets up the controller after the application finishes launching and
        suppresses the default dock icon (accessory activation policy).
        """

        def initWithController_(
            self, controller: VPNMenuBarController
        ) -> "VPNMenuBarAppDelegate":
            self = objc.super(VPNMenuBarAppDelegate, self).init()  # type: ignore[call-arg]
            if self is None:
                return None  # type: ignore[return-value]
            self._controller = controller
            return self

        def applicationDidFinishLaunching_(self, notification) -> None:  # type: ignore[misc]
            self._controller.setup()

        def applicationShouldTerminateAfterLastWindowClosed_(  # type: ignore[misc]
            self, app: AppKit.NSApplication
        ) -> bool:
            return False


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def run_menubar_app(
    model: VPNStatusModel,
    connect_action: Optional[Callable[[], None]] = None,
    disconnect_action: Optional[Callable[[], None]] = None,
) -> None:  # pragma: no cover – requires a running macOS display server
    """
    Start the macOS menu bar application and enter the NSRunLoop.

    This function **blocks** until the application is terminated (Quit menu
    item or SIGTERM).  Call it from the main thread.

    Parameters
    ----------
    model:
        Shared state model.  Pass the same instance to the VPN engine so it
        can call ``set_status``, ``update_traffic``, etc.
    connect_action:
        Zero-argument callable invoked on a background thread when the user
        clicks *Connect*.
    disconnect_action:
        Zero-argument callable invoked on a background thread when the user
        clicks *Disconnect*.

    Raises
    ------
    RuntimeError
        When PyObjC is not available (non-macOS platform).
    """
    if not _PYOBJC_AVAILABLE:
        raise RuntimeError(
            "PyObjC is required to run the macOS menu bar application.\n"
            "Install it with: pip install pyobjc-core pyobjc-framework-Cocoa"
        )

    app = AppKit.NSApplication.sharedApplication()
    # Accessory policy: no dock icon, no main menu
    app.setActivationPolicy_(AppKit.NSApplicationActivationPolicyAccessory)

    controller = VPNMenuBarController.alloc().initWithModel_(model)
    if connect_action is not None:
        controller.set_connect_action(connect_action)
    if disconnect_action is not None:
        controller.set_disconnect_action(disconnect_action)

    delegate = VPNMenuBarAppDelegate.alloc().initWithController_(controller)
    app.setDelegate_(delegate)

    logger.info("menubar_app_starting")
    app.run()
    logger.info("menubar_app_stopped")
