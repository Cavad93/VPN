#!/usr/bin/env bash
#
# VPN Auto-Update Script
#
# Pulls the latest code from GitHub every 15 minutes and applies updates
# WITHOUT breaking active VPN connections.
#
# Server (Go):   pull → rebuild binary → graceful restart via SIGTERM + systemd
# Client (Python): pull → modules updated on disk → next reconnect picks them up
# Diagnostics:   pull → script updated on disk → next run picks it up
#
# Usage:
#   # Server mode (rebuilds Go binary and restarts service)
#   ./auto_update.sh --mode server --repo-dir /opt/vpn --branch main
#
#   # Client mode (just pulls Python files, no restart needed)
#   ./auto_update.sh --mode client --repo-dir /opt/vpn --branch main
#
#   # Custom interval (default: 900 seconds = 15 min)
#   ./auto_update.sh --mode server --repo-dir /opt/vpn --interval 600
#
#   # One-shot (check once and exit)
#   ./auto_update.sh --mode server --repo-dir /opt/vpn --once
#
# Environment:
#   VPN_SERVICE_NAME  — systemd service name (default: cavadvpn)
#   VPN_BINARY_PATH   — path to server binary (default: <repo>/server/vpn-server)
#

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
MODE="server"
REPO_DIR=""
BRANCH="main"
INTERVAL=900
ONCE=false
SERVICE_NAME="${VPN_SERVICE_NAME:-cavadvpn}"
BINARY_NAME="vpn-server"
LOG_FILE="/var/log/vpn-auto-update.log"
REMOTE="origin"
MAX_RETRIES=4

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
usage() {
    echo "Usage: $0 --mode <server|client> --repo-dir <path> [options]"
    echo ""
    echo "Options:"
    echo "  --mode <server|client>  Update mode (default: server)"
    echo "  --repo-dir <path>       Path to the VPN repository (required)"
    echo "  --branch <name>         Git branch to track (default: main)"
    echo "  --interval <seconds>    Check interval (default: 900 = 15 min)"
    echo "  --once                  Check once and exit"
    echo "  --service <name>        Systemd service name (default: cavadvpn)"
    echo "  --log-file <path>       Log file path (default: /var/log/vpn-auto-update.log)"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)       MODE="$2"; shift 2 ;;
        --repo-dir)   REPO_DIR="$2"; shift 2 ;;
        --branch)     BRANCH="$2"; shift 2 ;;
        --interval)   INTERVAL="$2"; shift 2 ;;
        --once)       ONCE=true; shift ;;
        --service)    SERVICE_NAME="$2"; shift 2 ;;
        --log-file)   LOG_FILE="$2"; shift 2 ;;
        --help|-h)    usage ;;
        *)            echo "Unknown option: $1"; usage ;;
    esac
done

if [[ -z "$REPO_DIR" ]]; then
    echo "Error: --repo-dir is required"
    usage
fi

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log() {
    local level="$1"; shift
    local msg
    msg="$(date -u '+%Y-%m-%dT%H:%M:%SZ') [$level] $*"
    echo "$msg"
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Git operations with retry
# ---------------------------------------------------------------------------
git_fetch_with_retry() {
    local attempt=1
    local delay=2
    while [[ $attempt -le $MAX_RETRIES ]]; do
        if git -C "$REPO_DIR" fetch "$REMOTE" "$BRANCH" 2>>"$LOG_FILE"; then
            return 0
        fi
        log "WARN" "git fetch failed (attempt $attempt/$MAX_RETRIES), retrying in ${delay}s..."
        sleep "$delay"
        delay=$((delay * 2))
        attempt=$((attempt + 1))
    done
    log "ERROR" "git fetch failed after $MAX_RETRIES attempts"
    return 1
}

check_for_updates() {
    # Fetch latest from remote
    if ! git_fetch_with_retry; then
        return 1
    fi

    # Compare local HEAD with remote
    local local_hash remote_hash
    local_hash=$(git -C "$REPO_DIR" rev-parse HEAD)
    remote_hash=$(git -C "$REPO_DIR" rev-parse "$REMOTE/$BRANCH")

    if [[ "$local_hash" == "$remote_hash" ]]; then
        log "INFO" "Already up to date ($local_hash)"
        return 1  # no update needed
    fi

    log "INFO" "Update available: $local_hash → $remote_hash"
    return 0  # update available
}

apply_update() {
    log "INFO" "Pulling latest changes..."

    # Stash any local changes (shouldn't exist on deployment, but safety net)
    if ! git -C "$REPO_DIR" diff --quiet 2>/dev/null; then
        log "WARN" "Stashing local changes..."
        git -C "$REPO_DIR" stash push -m "auto-update-$(date +%s)" 2>>"$LOG_FILE"
    fi

    # Fast-forward merge (no merge commits)
    if ! git -C "$REPO_DIR" merge --ff-only "$REMOTE/$BRANCH" 2>>"$LOG_FILE"; then
        log "ERROR" "Fast-forward merge failed. Manual intervention needed."
        return 1
    fi

    local new_hash
    new_hash=$(git -C "$REPO_DIR" rev-parse --short HEAD)
    log "INFO" "Updated to $new_hash"
    return 0
}

# ---------------------------------------------------------------------------
# Server mode: rebuild + graceful restart
# ---------------------------------------------------------------------------
rebuild_server() {
    log "INFO" "Building server binary..."
    local server_dir="$REPO_DIR/server"
    local binary_path="$server_dir/$BINARY_NAME"
    local new_binary="${binary_path}.new"

    # Build new binary alongside the running one
    if ! (cd "$server_dir" && go build -o "$new_binary" -ldflags "-s -w" . 2>>"$LOG_FILE"); then
        log "ERROR" "Build failed! Keeping current binary."
        rm -f "$new_binary"
        return 1
    fi

    # Atomic swap: rename new binary over old one
    mv "$new_binary" "$binary_path"
    log "INFO" "Binary updated: $binary_path"
    return 0
}

graceful_restart_server() {
    # Check if running as a systemd service
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        log "INFO" "Restarting systemd service '$SERVICE_NAME'..."
        # systemd sends SIGTERM → server drains connections → exits → systemd restarts
        # Active VPN sessions will reconnect automatically via client auto-reconnect
        systemctl restart "$SERVICE_NAME" 2>>"$LOG_FILE"

        # Wait for service to come back
        local timeout=30
        local waited=0
        while [[ $waited -lt $timeout ]]; do
            if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
                log "INFO" "Service restarted successfully"
                return 0
            fi
            sleep 1
            waited=$((waited + 1))
        done
        log "ERROR" "Service did not restart within ${timeout}s"
        return 1
    fi

    # Not a systemd service — try SIGTERM to any running server process
    local pid_file="$REPO_DIR/server/vpn-server.pid"
    if [[ -f "$pid_file" ]]; then
        local pid
        pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            log "INFO" "Sending SIGTERM to PID $pid..."
            kill -TERM "$pid"
            # Wait for graceful shutdown (server closes TUN, drains connections)
            local timeout=30
            local waited=0
            while kill -0 "$pid" 2>/dev/null && [[ $waited -lt $timeout ]]; do
                sleep 1
                waited=$((waited + 1))
            done
            if kill -0 "$pid" 2>/dev/null; then
                log "WARN" "Server didn't stop in ${timeout}s, sending SIGKILL"
                kill -KILL "$pid" 2>/dev/null || true
            fi
        fi
    fi

    log "WARN" "No systemd service or PID file found. Binary updated but not restarted."
    log "WARN" "Restart the server manually to apply the update."
    return 0
}

do_server_update() {
    if ! rebuild_server; then
        return 1
    fi
    graceful_restart_server
}

# ---------------------------------------------------------------------------
# Client mode: just pull, Python picks up changes on next import
# ---------------------------------------------------------------------------
do_client_update() {
    # Python modules are loaded from disk — updated files are picked up on
    # the next reconnect cycle (auto-reconnect creates a fresh VPNClient).
    # No restart needed for the diagnostics script either.
    log "INFO" "Client files updated on disk. Changes will be active on next reconnect."

    # If there's a running diagnostics process, it will pick up the new
    # vpn_diagnostics.py on the next iteration (it re-reads no modules).
    # For the VPN client itself: the reconnect module creates a fresh
    # VPNClient instance, so updated core.py/perf_collector.py will be used.
    return 0
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
main() {
    log "INFO" "Auto-update started: mode=$MODE repo=$REPO_DIR branch=$BRANCH interval=${INTERVAL}s"

    # Verify repo exists
    if [[ ! -d "$REPO_DIR/.git" ]]; then
        log "ERROR" "$REPO_DIR is not a git repository"
        exit 1
    fi

    while true; do
        if check_for_updates; then
            if apply_update; then
                case "$MODE" in
                    server) do_server_update ;;
                    client) do_client_update ;;
                    *)      log "ERROR" "Unknown mode: $MODE"; exit 1 ;;
                esac
            fi
        fi

        if [[ "$ONCE" == true ]]; then
            log "INFO" "One-shot mode, exiting."
            break
        fi

        log "INFO" "Next check in ${INTERVAL}s..."
        sleep "$INTERVAL"
    done
}

# Trap signals for clean exit
trap 'log "INFO" "Received signal, exiting..."; exit 0' SIGINT SIGTERM

main
