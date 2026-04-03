#!/bin/bash
# run_tests.sh — Runs the Python compatibility tests for the iOS CavadVPN implementation.
set -euo pipefail
cd "$(dirname "$0")"
echo "Running iOS protocol compatibility tests..."
python3 -m pytest test_compat.py -v "$@"
