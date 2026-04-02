#!/usr/bin/env python3
"""
cavadvpn_cli.py — CavadVPN command-line interface.

Provides connect/disconnect/status/config commands for the CavadVPN client.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Allow running from installed location as well as from source
_HERE = Path(__file__).parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

DEFAULT_CONFIG = Path.home() / ".config" / "cavadvpn" / "config.yaml"


def _load_config(path: Path) -> dict:
    """Load YAML config; return empty dict if file doesn't exist."""
    try:
        import yaml  # type: ignore
        with open(path) as fh:
            return yaml.safe_load(fh) or {}
    except FileNotFoundError:
        return {}
    except ImportError:
        # yaml not installed — return empty
        return {}


def _save_config(path: Path, cfg: dict) -> None:
    """Save config dict to YAML file, creating parent dirs as needed."""
    try:
        import yaml  # type: ignore
    except ImportError:
        print("ERROR: pyyaml not installed. Run: pip install pyyaml", file=sys.stderr)
        sys.exit(1)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as fh:
        yaml.safe_dump(cfg, fh, default_flow_style=False)


# ── Subcommands ───────────────────────────────────────────────────────────────

def cmd_status(_args: argparse.Namespace) -> int:
    """Show current VPN connection status."""
    # Attempt to read pid file written by connect command
    pid_file = Path.home() / ".config" / "cavadvpn" / "cavadvpn.pid"
    if pid_file.exists():
        pid = pid_file.read_text().strip()
        try:
            os.kill(int(pid), 0)  # signal 0 = existence check
            print(f"Status: CONNECTED (pid={pid})")
            return 0
        except (ProcessLookupError, ValueError):
            pass
    print("Status: DISCONNECTED")
    return 0


def cmd_connect(args: argparse.Namespace) -> int:
    """Connect to VPN server."""
    config_path = Path(args.config)
    cfg = _load_config(config_path)

    server = args.server or cfg.get("server")
    if not server:
        print(
            "ERROR: Server address required. Use --server HOST:PORT or set 'server' in config.",
            file=sys.stderr,
        )
        return 1

    key_file = args.key or cfg.get("private_key_file") or str(
        Path.home() / ".config" / "cavadvpn" / "client.key"
    )

    print(f"Connecting to {server} ...")

    try:
        from core import VPNConfig, VPNClient  # type: ignore

        vpn_cfg = VPNConfig(
            server_addr=server.split(":")[0],
            server_port=int(server.split(":")[1]) if ":" in server else 443,
            private_key_file=key_file,
        )
        client = VPNClient(vpn_cfg)
        client.connect()
        print("Connected.")

        # Write pid file
        pid_file = Path.home() / ".config" / "cavadvpn" / "cavadvpn.pid"
        pid_file.parent.mkdir(parents=True, exist_ok=True)
        pid_file.write_text(str(os.getpid()))

        # Block until interrupted
        import signal
        import time

        def _handle_signal(_sig, _frame):
            print("\nDisconnecting ...")
            client.disconnect()
            pid_file.unlink(missing_ok=True)
            sys.exit(0)

        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)

        print("Press Ctrl+C to disconnect.")
        while True:
            time.sleep(1)

    except ImportError as exc:
        print(f"ERROR: Failed to import VPN core: {exc}", file=sys.stderr)
        print("Ensure the client library is installed in the virtualenv.", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


def cmd_disconnect(_args: argparse.Namespace) -> int:
    """Disconnect from VPN (sends SIGTERM to running process)."""
    pid_file = Path.home() / ".config" / "cavadvpn" / "cavadvpn.pid"
    if not pid_file.exists():
        print("No active VPN connection found.")
        return 0
    pid = pid_file.read_text().strip()
    try:
        os.kill(int(pid), 15)  # SIGTERM
        pid_file.unlink(missing_ok=True)
        print("Disconnected.")
    except ProcessLookupError:
        print("Process not found — cleaning up pid file.")
        pid_file.unlink(missing_ok=True)
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    """Get or set configuration values."""
    config_path = Path(args.config)
    cfg = _load_config(config_path)

    if args.set:
        for pair in args.set:
            if "=" not in pair:
                print(f"ERROR: expected KEY=VALUE, got: {pair}", file=sys.stderr)
                return 1
            key, _, value = pair.partition("=")
            cfg[key.strip()] = value.strip()
        _save_config(config_path, cfg)
        print(f"Config saved to {config_path}")
    else:
        if cfg:
            for k, v in cfg.items():
                print(f"{k} = {v}")
        else:
            print(f"No config at {config_path}")
    return 0


def cmd_version(_args: argparse.Namespace) -> int:
    """Print version."""
    print("CavadVPN 1.0.0")
    return 0


# ── Argument parser ───────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cavadvpn",
        description="CavadVPN — secure VPN client",
    )
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG),
        metavar="PATH",
        help="path to config file (default: %(default)s)",
    )

    subs = parser.add_subparsers(dest="command", metavar="COMMAND")

    subs.add_parser("status", help="show connection status")

    conn = subs.add_parser("connect", help="connect to VPN server")
    conn.add_argument("--server", metavar="HOST:PORT", help="server address")
    conn.add_argument("--key", metavar="FILE", help="private key file")

    subs.add_parser("disconnect", help="disconnect from VPN")

    cfg = subs.add_parser("config", help="get or set configuration")
    cfg.add_argument("--set", nargs="+", metavar="KEY=VALUE", help="set config values")

    subs.add_parser("version", help="print version")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    dispatch = {
        "status": cmd_status,
        "connect": cmd_connect,
        "disconnect": cmd_disconnect,
        "config": cmd_config,
        "version": cmd_version,
    }

    if args.command is None:
        parser.print_help()
        return 0

    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
