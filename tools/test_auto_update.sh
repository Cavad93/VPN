#!/usr/bin/env bash
#
# Tests for auto_update.sh
# Uses a temporary git repo to simulate updates.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AUTO_UPDATE="$SCRIPT_DIR/auto_update.sh"
PASS=0
FAIL=0
TMPDIR=""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

setup() {
    TMPDIR=$(mktemp -d)
    REMOTE_REPO="$TMPDIR/remote.git"
    LOCAL_REPO="$TMPDIR/local"

    # Create a bare remote repo with 'main' as default branch
    git init --bare --initial-branch=main "$REMOTE_REPO" >/dev/null 2>&1

    # Clone it as the "deployment" repo
    git clone "$REMOTE_REPO" "$LOCAL_REPO" >/dev/null 2>&1

    # Configure git user and disable signing for test repos
    git -C "$LOCAL_REPO" config user.email "test@test.com" >/dev/null 2>&1
    git -C "$LOCAL_REPO" config user.name "Test" >/dev/null 2>&1
    git -C "$LOCAL_REPO" config commit.gpgsign false >/dev/null 2>&1
    git -C "$LOCAL_REPO" config tag.gpgsign false >/dev/null 2>&1

    # Add initial commit
    echo "initial" > "$LOCAL_REPO/file.txt"
    mkdir -p "$LOCAL_REPO/server"
    echo "package main" > "$LOCAL_REPO/server/main.go"
    git -C "$LOCAL_REPO" add -A >/dev/null 2>&1
    git -C "$LOCAL_REPO" commit -m "initial" >/dev/null 2>&1
    git -C "$LOCAL_REPO" branch -M main >/dev/null 2>&1
    git -C "$LOCAL_REPO" push -u origin main >/dev/null 2>&1
}

teardown() {
    if [[ -n "$TMPDIR" && -d "$TMPDIR" ]]; then
        rm -rf "$TMPDIR"
    fi
}

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        echo "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc (expected='$expected', actual='$actual')"
        FAIL=$((FAIL + 1))
    fi
}

assert_contains() {
    local desc="$1" needle="$2" haystack="$3"
    if echo "$haystack" | grep -q "$needle"; then
        echo "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc (expected to contain '$needle')"
        FAIL=$((FAIL + 1))
    fi
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

test_no_updates_when_up_to_date() {
    echo "TEST: no updates when up to date"
    setup

    output=$("$AUTO_UPDATE" --mode client --repo-dir "$LOCAL_REPO" --branch main --once --log-file "$TMPDIR/test.log" 2>&1 || true)
    assert_contains "reports up to date" "Already up to date" "$output"

    teardown
}

test_detects_new_commit() {
    echo "TEST: detects new commit"
    setup

    # Make a new commit on the remote (via a temp clone)
    local tmp_clone="$TMPDIR/tmp_clone"
    git clone "$REMOTE_REPO" "$tmp_clone" >/dev/null 2>&1
    git -C "$tmp_clone" config user.email "test@test.com" >/dev/null 2>&1
    git -C "$tmp_clone" config user.name "Test" >/dev/null 2>&1
    git -C "$tmp_clone" config commit.gpgsign false >/dev/null 2>&1
    echo "updated" > "$tmp_clone/file.txt"
    git -C "$tmp_clone" add -A >/dev/null 2>&1
    git -C "$tmp_clone" commit -m "update" >/dev/null 2>&1
    git -C "$tmp_clone" branch -M main >/dev/null 2>&1
    git -C "$tmp_clone" push origin main >/dev/null 2>&1

    output=$("$AUTO_UPDATE" --mode client --repo-dir "$LOCAL_REPO" --branch main --once --log-file "$TMPDIR/test.log" 2>&1 || true)
    assert_contains "detects update" "Update available" "$output"
    assert_contains "applies update" "Updated to" "$output"

    # Verify the file was updated
    local content
    content=$(cat "$LOCAL_REPO/file.txt")
    assert_eq "file content updated" "updated" "$content"

    teardown
}

test_client_mode_no_restart() {
    echo "TEST: client mode does not restart"
    setup

    # Push an update
    local tmp_clone="$TMPDIR/tmp_clone"
    git clone "$REMOTE_REPO" "$tmp_clone" >/dev/null 2>&1
    git -C "$tmp_clone" config user.email "test@test.com" >/dev/null 2>&1
    git -C "$tmp_clone" config user.name "Test" >/dev/null 2>&1
    git -C "$tmp_clone" config commit.gpgsign false >/dev/null 2>&1
    echo "v2" > "$tmp_clone/file.txt"
    git -C "$tmp_clone" add -A >/dev/null 2>&1
    git -C "$tmp_clone" commit -m "v2" >/dev/null 2>&1
    git -C "$tmp_clone" branch -M main >/dev/null 2>&1
    git -C "$tmp_clone" push origin main >/dev/null 2>&1

    output=$("$AUTO_UPDATE" --mode client --repo-dir "$LOCAL_REPO" --branch main --once --log-file "$TMPDIR/test.log" 2>&1 || true)
    assert_contains "client mode message" "Changes will be active on next reconnect" "$output"

    teardown
}

test_invalid_repo_dir() {
    echo "TEST: invalid repo dir exits with error"
    output=$("$AUTO_UPDATE" --mode client --repo-dir "/tmp/nonexistent_vpn_xyz" --branch main --once --log-file /dev/null 2>&1 || true)
    assert_contains "error message" "not a git repository" "$output"
}

test_help_flag() {
    echo "TEST: --help prints usage"
    output=$("$AUTO_UPDATE" --help 2>&1 || true)
    assert_contains "shows usage" "Usage:" "$output"
}

test_log_file_created() {
    echo "TEST: log file is written"
    setup

    local logfile="$TMPDIR/update.log"
    "$AUTO_UPDATE" --mode client --repo-dir "$LOCAL_REPO" --branch main --once --log-file "$logfile" >/dev/null 2>&1 || true

    if [[ -f "$logfile" ]]; then
        echo "  PASS: log file exists"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: log file not created"
        FAIL=$((FAIL + 1))
    fi

    teardown
}

# ---------------------------------------------------------------------------
# Run all tests
# ---------------------------------------------------------------------------
echo "Running auto_update.sh tests..."
echo ""

test_no_updates_when_up_to_date
test_detects_new_commit
test_client_mode_no_restart
test_invalid_repo_dir
test_help_flag
test_log_file_created

echo ""
echo "Results: $PASS passed, $FAIL failed"

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
