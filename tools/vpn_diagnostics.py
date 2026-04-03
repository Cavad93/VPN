#!/usr/bin/env python3
"""
VPN Performance Diagnostics Tool

Collects metrics from the VPN server and client perf endpoints, sends them
to Claude Sonnet 4.6 for analysis, and saves reports to a file.

Usage:
    # One-shot analysis
    python3 vpn_diagnostics.py --server-url http://127.0.0.1:8080

    # Continuous monitoring every 5 minutes
    python3 vpn_diagnostics.py --server-url http://127.0.0.1:8080 --interval 300

    # With client metrics
    python3 vpn_diagnostics.py --server-url http://127.0.0.1:8080 \
        --client-url http://127.0.0.1:9091

    # Adjust Claude API request frequency (max requests per hour)
    python3 vpn_diagnostics.py --server-url http://127.0.0.1:8080 \
        --max-requests-per-hour 4

Environment:
    ANTHROPIC_API_KEY  — required; your Anthropic API key
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MODEL_ID = "claude-sonnet-4-6"
API_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_REPORT_FILE = "vpn_perf_report.jsonl"
DEFAULT_MAX_REQUESTS_PER_HOUR = 12  # one every 5 min
DEFAULT_INTERVAL_SECONDS = 300      # 5 min
MAX_TOKENS = 4096

# ---------------------------------------------------------------------------
# Metrics collection
# ---------------------------------------------------------------------------


def fetch_json(url: str, token: str = "") -> Optional[dict]:
    """GET a JSON endpoint. Returns None on failure."""
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
        print(f"[warn] Failed to fetch {url}: {e}", file=sys.stderr)
        return None


def collect_server_metrics(base_url: str, token: str = "") -> dict:
    """Collect all available metrics from the VPN server API."""
    metrics = {}
    perf = fetch_json(f"{base_url}/api/v1/perf", token)
    if perf:
        metrics["perf"] = perf
    sessions = fetch_json(f"{base_url}/api/v1/sessions", token)
    if sessions is not None:
        metrics["sessions"] = sessions
    stats = fetch_json(f"{base_url}/api/v1/stats", token)
    if stats:
        metrics["stats"] = stats
    health = fetch_json(f"{base_url}/api/v1/health")
    if health:
        metrics["health"] = health
    return metrics


def collect_client_metrics(base_url: str) -> Optional[dict]:
    """Collect metrics from the client's local perf HTTP endpoint."""
    return fetch_json(f"{base_url}/perf")


# ---------------------------------------------------------------------------
# Claude API interaction
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are a VPN performance diagnostics expert. You analyze performance metrics
from a custom VPN implementation and identify bottlenecks, anomalies, and
optimization opportunities.

The VPN stack:
- Server: Go, TCP transport with TLS obfuscation (ObfsConn), Noise_XX encryption,
  stream multiplexing (Mux), TUN device, multi-connection bonding.
- Client: Python, same protocol stack, optional traffic shaping and padding.

Metrics include per-stage latency histograms (p50/p95/p99 in microseconds),
packet counts, byte counts, congestion window, retransmit counts, session info.

For each analysis:
1. Identify the TOP 3 bottlenecks by latency contribution.
2. Flag any anomalies (unusual p99 spikes, high retransmit rate, etc.).
3. Give CONCRETE recommendations with expected impact.
4. Rate overall VPN health: GOOD / DEGRADED / CRITICAL.

Be concise. Use tables where helpful. Focus on actionable insights.
"""


def analyze_with_claude(
    api_key: str,
    server_metrics: dict,
    client_metrics: Optional[dict],
    previous_report: Optional[dict] = None,
) -> dict:
    """Send metrics to Claude Sonnet 4.6 and get analysis."""

    user_content = "## Current VPN Metrics\n\n"
    user_content += "### Server Metrics\n```json\n"
    user_content += json.dumps(server_metrics, indent=2, default=str)
    user_content += "\n```\n\n"

    if client_metrics:
        user_content += "### Client Metrics\n```json\n"
        user_content += json.dumps(client_metrics, indent=2, default=str)
        user_content += "\n```\n\n"

    if previous_report:
        user_content += "### Previous Analysis (for trend comparison)\n```\n"
        user_content += previous_report.get("analysis", "N/A")
        user_content += "\n```\n\n"

    user_content += (
        "Analyze these metrics. Identify bottlenecks, anomalies, and "
        "give concrete optimization recommendations for code changes."
    )

    payload = {
        "model": MODEL_ID,
        "max_tokens": MAX_TOKENS,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": user_content}],
    }

    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        API_URL,
        data=data,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            result = json.loads(resp.read())
        # Extract text from response
        text = ""
        for block in result.get("content", []):
            if block.get("type") == "text":
                text += block["text"]
        usage = result.get("usage", {})
        return {
            "analysis": text,
            "input_tokens": usage.get("input_tokens", 0),
            "output_tokens": usage.get("output_tokens", 0),
            "model": MODEL_ID,
        }
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        return {"error": f"HTTP {e.code}: {body}", "analysis": ""}
    except Exception as e:
        return {"error": str(e), "analysis": ""}


# ---------------------------------------------------------------------------
# Report management
# ---------------------------------------------------------------------------


def save_report(report: dict, filepath: str) -> None:
    """Append a report as one JSON line to the report file."""
    with open(filepath, "a") as f:
        f.write(json.dumps(report, default=str) + "\n")


def load_last_report(filepath: str) -> Optional[dict]:
    """Load the most recent report from the JSONL file."""
    path = Path(filepath)
    if not path.exists():
        return None
    try:
        lines = path.read_text().strip().split("\n")
        if lines and lines[-1]:
            return json.loads(lines[-1])
    except (json.JSONDecodeError, IndexError):
        pass
    return None


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


class RateLimiter:
    """Simple token-bucket rate limiter."""

    def __init__(self, max_per_hour: int):
        self._interval = 3600.0 / max(max_per_hour, 1)
        self._last_call = 0.0

    def wait(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_call
        if elapsed < self._interval:
            wait_time = self._interval - elapsed
            print(f"[rate-limit] Waiting {wait_time:.0f}s before next API call...")
            time.sleep(wait_time)
        self._last_call = time.monotonic()


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------


def run_once(
    args: argparse.Namespace,
    api_key: str,
    rate_limiter: RateLimiter,
    report_file: str,
) -> dict:
    """Collect metrics, analyze, save report. Returns the report dict."""
    print(f"\n{'='*60}")
    print(f"[{datetime.now(timezone.utc).isoformat()}] Collecting metrics...")

    server_metrics = collect_server_metrics(args.server_url, args.api_token or "")
    if not server_metrics:
        print("[error] No server metrics available. Is the server running?")
        return {"error": "no server metrics"}

    client_metrics = None
    if args.client_url:
        client_metrics = collect_client_metrics(args.client_url)
        if not client_metrics:
            print("[warn] No client metrics available.")

    previous = load_last_report(report_file)

    print(f"[info] Sending to Claude {MODEL_ID} for analysis...")
    rate_limiter.wait()

    result = analyze_with_claude(api_key, server_metrics, client_metrics, previous)

    if result.get("error"):
        print(f"[error] Claude API: {result['error']}", file=sys.stderr)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "server_metrics": server_metrics,
        "client_metrics": client_metrics,
        **result,
    }

    save_report(report, report_file)
    print(f"[info] Report saved to {report_file}")

    if result.get("analysis"):
        print(f"\n{'─'*60}")
        print("ANALYSIS:")
        print(f"{'─'*60}")
        print(result["analysis"])
        print(f"{'─'*60}")
        tokens = result.get("input_tokens", 0) + result.get("output_tokens", 0)
        print(f"[tokens] input={result.get('input_tokens',0)} "
              f"output={result.get('output_tokens',0)} total={tokens}")

    return report


def main():
    parser = argparse.ArgumentParser(
        description="VPN Performance Diagnostics with Claude Sonnet 4.6",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--server-url",
        required=True,
        help="VPN server API base URL (e.g. http://127.0.0.1:8080)",
    )
    parser.add_argument(
        "--client-url",
        default=None,
        help="Client perf HTTP endpoint (e.g. http://127.0.0.1:9091)",
    )
    parser.add_argument(
        "--api-token",
        default=os.environ.get("VPN_API_TOKEN", ""),
        help="VPN server API Bearer token (or VPN_API_TOKEN env var)",
    )
    parser.add_argument(
        "--report-file",
        default=DEFAULT_REPORT_FILE,
        help=f"Path to JSONL report file (default: {DEFAULT_REPORT_FILE})",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=0,
        help="Seconds between checks (0 = one-shot, default: 0)",
    )
    parser.add_argument(
        "--max-requests-per-hour",
        type=int,
        default=DEFAULT_MAX_REQUESTS_PER_HOUR,
        help=f"Max Claude API requests per hour (default: {DEFAULT_MAX_REQUESTS_PER_HOUR})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Collect and print metrics without calling Claude API",
    )

    args = parser.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key and not args.dry_run:
        print("[error] ANTHROPIC_API_KEY environment variable is required.",
              file=sys.stderr)
        sys.exit(1)

    report_file = args.report_file
    rate_limiter = RateLimiter(args.max_requests_per_hour)

    print(f"VPN Diagnostics — Claude {MODEL_ID}")
    print(f"  Server: {args.server_url}")
    print(f"  Client: {args.client_url or 'not configured'}")
    print(f"  Report: {report_file}")
    print(f"  Rate limit: {args.max_requests_per_hour} req/hour")
    print(f"  Interval: {'one-shot' if args.interval == 0 else f'{args.interval}s'}")

    if args.dry_run:
        print("\n[dry-run] Collecting metrics only (no Claude API call)...")
        server_metrics = collect_server_metrics(args.server_url, args.api_token or "")
        print(json.dumps(server_metrics, indent=2, default=str))
        if args.client_url:
            client_metrics = collect_client_metrics(args.client_url)
            if client_metrics:
                print(json.dumps(client_metrics, indent=2, default=str))
        return

    # Handle Ctrl+C gracefully
    stop = False

    def on_signal(signum, frame):
        nonlocal stop
        stop = True
        print("\n[info] Shutting down...")

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    if args.interval == 0:
        run_once(args, api_key, rate_limiter, report_file)
    else:
        print(f"\n[info] Starting continuous monitoring (Ctrl+C to stop)...")
        while not stop:
            run_once(args, api_key, rate_limiter, report_file)
            if stop:
                break
            # Sleep in small increments to respond to signals quickly
            for _ in range(args.interval):
                if stop:
                    break
                time.sleep(1)

    print("[info] Done.")


if __name__ == "__main__":
    main()
