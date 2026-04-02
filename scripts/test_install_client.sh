#!/usr/bin/env bash
# test_install_client.sh — Unit tests for install_client.sh helper functions
#
# Tests run on Linux too (does NOT require macOS or pkgbuild).
# Only the helper/logic functions are tested; macOS-specific commands
# (pkgbuild, productbuild, xcrun) are mocked.
#
# Usage:
#   cd scripts && bash test_install_client.sh
#   # or from repo root:
#   bash scripts/test_install_client.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Minimal test framework ────────────────────────────────────────────────────
PASS=0
FAIL=0
_CURRENT_TEST=""

start_test() { _CURRENT_TEST="$1"; }

ok() {
    local desc="$1"
    PASS=$((PASS + 1))
    echo "  PASS: $desc"
}

fail() {
    local desc="$1"
    FAIL=$((FAIL + 1))
    echo "  FAIL: $desc  [test: $_CURRENT_TEST]"
}

assert_eq() {
    local got="$1" expected="$2" msg="${3:-}"
    if [[ "$got" == "$expected" ]]; then
        ok "${msg:-assert_eq '$got' == '$expected'}"
    else
        fail "${msg:-expected '$expected' but got '$got'}"
    fi
}

assert_contains() {
    local haystack="$1" needle="$2" msg="${3:-}"
    if [[ "$haystack" == *"$needle"* ]]; then
        ok "${msg:-output contains '$needle'}"
    else
        fail "${msg:-expected output to contain '$needle', got: $haystack}"
    fi
}

assert_file_exists() {
    local path="$1" msg="${2:-file exists: $1}"
    if [[ -f "$path" ]]; then ok "$msg"; else fail "$msg (not found)"; fi
}

assert_dir_exists() {
    local path="$1" msg="${2:-dir exists: $1}"
    if [[ -d "$path" ]]; then ok "$msg"; else fail "$msg (not found)"; fi
}

assert_executable() {
    local path="$1" msg="${2:-executable: $1}"
    if [[ -x "$path" ]]; then ok "$msg"; else fail "$msg (not executable)"; fi
}

assert_zero() {
    local rc="$1" msg="${2:-exit code is 0}"
    if [[ "$rc" -eq 0 ]]; then ok "$msg"; else fail "$msg (got $rc)"; fi
}

assert_nonzero() {
    local rc="$1" msg="${2:-exit code is non-zero}"
    if [[ "$rc" -ne 0 ]]; then ok "$msg"; else fail "$msg (got 0)"; fi
}

summary() {
    echo ""
    echo "================================"
    echo "  Tests: $((PASS + FAIL))  Pass: $PASS  Fail: $FAIL"
    echo "================================"
    [[ $FAIL -eq 0 ]]
}

# ── Source helpers from install_client.sh (without running main) ──────────────
# We extract only the helper functions so tests work on Linux.
_source_helpers() {
    # Temporarily override require_macos to a no-op so we can source on Linux
    require_macos() { :; }
    # Source the script but skip main execution
    # We do this by defining main as a no-op before sourcing
    main() { :; }
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/install_client.sh"
}

# ── Test: parse_args default values ──────────────────────────────────────────
test_parse_args_defaults() {
    start_test "parse_args defaults"

    # Reset globals that parse_args modifies
    VERSION="1.0.0"
    OUTPUT_DIR="$REPO_ROOT/dist"
    SIGN_IDENTITY=""
    NOTARIZE=false

    parse_args  # no args

    assert_eq "$VERSION" "1.0.0" "default version"
    assert_eq "$OUTPUT_DIR" "$REPO_ROOT/dist" "default output dir"
    assert_eq "$SIGN_IDENTITY" "" "default sign identity empty"
    assert_eq "$NOTARIZE" "false" "default notarize false"
}

test_parse_args_flags() {
    start_test "parse_args flags"

    VERSION="1.0.0"
    OUTPUT_DIR="$REPO_ROOT/dist"
    SIGN_IDENTITY=""
    NOTARIZE=false
    APPLE_ID=""
    APPLE_PASSWORD=""
    TEAM_ID=""

    parse_args --version 2.3.4 --output-dir /tmp/out --sign-identity "Developer ID Application: Acme" \
               --notarize --apple-id a@b.com --apple-password secret --team-id ABCD1234

    assert_eq "$VERSION" "2.3.4" "version flag"
    assert_eq "$OUTPUT_DIR" "/tmp/out" "output-dir flag"
    assert_eq "$SIGN_IDENTITY" "Developer ID Application: Acme" "sign-identity flag"
    assert_eq "$NOTARIZE" "true" "notarize flag"
    assert_eq "$APPLE_ID" "a@b.com" "apple-id flag"
    assert_eq "$APPLE_PASSWORD" "secret" "apple-password flag"
    assert_eq "$TEAM_ID" "ABCD1234" "team-id flag"
}

test_parse_args_short_flags() {
    start_test "parse_args short flags"

    VERSION="1.0.0"
    OUTPUT_DIR="$REPO_ROOT/dist"
    SIGN_IDENTITY=""

    parse_args -v 0.9.0 -o /my/dist -s "My Identity"

    assert_eq "$VERSION" "0.9.0" "short -v flag"
    assert_eq "$OUTPUT_DIR" "/my/dist" "short -o flag"
    assert_eq "$SIGN_IDENTITY" "My Identity" "short -s flag"
}

# ── Test: validate_args ────────────────────────────────────────────────────────
test_validate_args_no_notarize() {
    start_test "validate_args without notarize"

    NOTARIZE=false
    SIGN_IDENTITY=""
    REPO_ROOT_SAVE="$REPO_ROOT"
    REPO_ROOT="$_TMP_REPO"

    validate_args
    local rc=$?
    assert_zero "$rc" "validate_args succeeds without notarize"

    REPO_ROOT="$REPO_ROOT_SAVE"
}

test_validate_args_notarize_missing_fields() {
    start_test "validate_args notarize missing fields"

    # Run validate_args (already sourced) in a subshell with the needed vars.
    # die() calls exit which terminates the subshell, not the test runner.
    local sub_rc=0
    (
        NOTARIZE=true
        SIGN_IDENTITY=""
        APPLE_ID=""
        REPO_ROOT="$_TMP_REPO"
        validate_args 2>/dev/null
    ) && sub_rc=0 || sub_rc=$?
    assert_nonzero "$sub_rc" "validate_args fails when notarize but no sign-identity"
}

test_validate_args_missing_client_dir() {
    start_test "validate_args missing client dir"

    local sub_rc=0
    (
        NOTARIZE=false
        SIGN_IDENTITY=""
        REPO_ROOT="/tmp/nonexistent_$$"
        validate_args 2>/dev/null
    ) && sub_rc=0 || sub_rc=$?
    assert_nonzero "$sub_rc" "validate_args fails when client dir missing"
}

# ── Test: copy_client_files ───────────────────────────────────────────────────
test_copy_client_files() {
    start_test "copy_client_files"

    local tmp_build
    tmp_build="$(mktemp -d)"
    PAYLOAD_DIR="$tmp_build/payload"
    mkdir -p "$PAYLOAD_DIR/Applications/CavadVPN"

    REPO_ROOT="$_TMP_REPO"
    copy_client_files

    assert_file_exists "$PAYLOAD_DIR/Applications/CavadVPN/requirements.txt" \
        "requirements.txt copied"
    assert_file_exists "$PAYLOAD_DIR/Applications/CavadVPN/core.py" \
        "core.py copied"
    assert_file_exists "$PAYLOAD_DIR/Applications/CavadVPN/cavadvpn_cli.py" \
        "cavadvpn_cli.py copied"
    assert_file_exists "$PAYLOAD_DIR/Applications/CavadVPN/menubar_main.py" \
        "menubar_main.py created"

    rm -rf "$tmp_build"
}

# ── Test: copy_scripts ────────────────────────────────────────────────────────
test_copy_scripts() {
    start_test "copy_scripts"

    local tmp_build
    tmp_build="$(mktemp -d)"
    SCRIPTS_DIR="$tmp_build/scripts"
    mkdir -p "$SCRIPTS_DIR"

    copy_scripts

    assert_file_exists "$SCRIPTS_DIR/preinstall"    "preinstall copied"
    assert_file_exists "$SCRIPTS_DIR/postinstall"   "postinstall copied"
    assert_file_exists "$SCRIPTS_DIR/preuninstall"  "preuninstall copied"
    assert_executable  "$SCRIPTS_DIR/preinstall"    "preinstall is executable"
    assert_executable  "$SCRIPTS_DIR/postinstall"   "postinstall is executable"

    rm -rf "$tmp_build"
}

# ── Test: copy_resources ──────────────────────────────────────────────────────
test_copy_resources() {
    start_test "copy_resources"

    local tmp_build
    tmp_build="$(mktemp -d)"
    RESOURCES_DIR="$tmp_build/resources"
    mkdir -p "$RESOURCES_DIR"

    copy_resources

    assert_file_exists "$RESOURCES_DIR/welcome.html"    "welcome.html copied"
    assert_file_exists "$RESOURCES_DIR/readme.html"     "readme.html copied"
    assert_file_exists "$RESOURCES_DIR/license.html"    "license.html copied"
    assert_file_exists "$RESOURCES_DIR/conclusion.html" "conclusion.html copied"

    rm -rf "$tmp_build"
}

# ── Test: log helpers output correct prefix ───────────────────────────────────
test_log_helpers() {
    start_test "log helpers"

    local out
    out="$(log_info "test message")"
    assert_contains "$out" "[INFO]" "log_info prefix"

    out="$(log_success "done")"
    assert_contains "$out" "[SUCCESS]" "log_success prefix"

    out="$(log_warn "watch out")"
    assert_contains "$out" "[WARN]" "log_warn prefix"

    out="$(log_error "oops" 2>&1)"
    assert_contains "$out" "[ERROR]" "log_error prefix"
}

# ── Test: require_cmd ─────────────────────────────────────────────────────────
test_require_cmd_existing() {
    start_test "require_cmd existing"

    set +e
    require_cmd bash
    local rc=$?
    set -e
    assert_zero "$rc" "require_cmd bash succeeds"
}

test_require_cmd_missing() {
    start_test "require_cmd missing"

    local sub_rc=0
    (require_cmd __nonexistent_cmd_xyz__ 2>/dev/null) && sub_rc=0 || sub_rc=$?
    assert_nonzero "$sub_rc" "require_cmd fails for missing command"
}

# ── Test: preinstall script syntax ────────────────────────────────────────────
test_preinstall_syntax() {
    start_test "preinstall bash syntax"

    bash -n "$SCRIPT_DIR/macos_pkg/scripts/preinstall"
    local rc=$?
    assert_zero "$rc" "preinstall has valid bash syntax"
}

test_postinstall_syntax() {
    start_test "postinstall bash syntax"

    bash -n "$SCRIPT_DIR/macos_pkg/scripts/postinstall"
    local rc=$?
    assert_zero "$rc" "postinstall has valid bash syntax"
}

test_preuninstall_syntax() {
    start_test "preuninstall bash syntax"

    bash -n "$SCRIPT_DIR/macos_pkg/scripts/preuninstall"
    local rc=$?
    assert_zero "$rc" "preuninstall has valid bash syntax"
}

test_install_client_syntax() {
    start_test "install_client.sh bash syntax"

    bash -n "$SCRIPT_DIR/install_client.sh"
    local rc=$?
    assert_zero "$rc" "install_client.sh has valid bash syntax"
}

# ── Test: distribution.xml is valid XML ───────────────────────────────────────
test_distribution_xml() {
    start_test "distribution.xml validity"

    local dist_xml="$SCRIPT_DIR/macos_pkg/distribution.xml"
    assert_file_exists "$dist_xml" "distribution.xml exists"

    # Check basic XML structure with python3 or xmllint
    if command -v python3 &>/dev/null; then
        python3 -c "
import xml.etree.ElementTree as ET
ET.parse('$dist_xml')
" && ok "distribution.xml is valid XML" || fail "distribution.xml XML parse error"
    elif command -v xmllint &>/dev/null; then
        xmllint --noout "$dist_xml" && ok "distribution.xml valid (xmllint)" || fail "xmllint error"
    else
        ok "distribution.xml exists (skipped XML validation — no parser found)"
    fi

    # Check required elements
    local content
    content="$(cat "$dist_xml")"
    assert_contains "$content" "com.cavadvpn" "distribution.xml has identifier"
    assert_contains "$content" "installer-gui-script" "distribution.xml has root element"
    assert_contains "$content" "choices-outline" "distribution.xml has choices"
}

# ── Test: HTML resources are well-formed ──────────────────────────────────────
test_html_resources() {
    start_test "HTML resources"

    for html in welcome.html readme.html license.html conclusion.html; do
        local path="$SCRIPT_DIR/macos_pkg/resources/$html"
        assert_file_exists "$path"

        local content
        content="$(cat "$path")"
        assert_contains "$content" "<!DOCTYPE html>" "$html has DOCTYPE"
        assert_contains "$content" "<body>" "$html has body tag"
    done
}

# ── Test: CLI entry point syntax ─────────────────────────────────────────────
test_cli_syntax() {
    start_test "cavadvpn_cli.py syntax"

    python3 -m py_compile "$REPO_ROOT/client/cavadvpn_cli.py"
    local rc=$?
    assert_zero "$rc" "cavadvpn_cli.py has valid Python syntax"
}

test_cli_help() {
    start_test "cavadvpn_cli.py --help"

    local out
    out="$(python3 "$REPO_ROOT/client/cavadvpn_cli.py" --help 2>&1)"
    assert_contains "$out" "cavadvpn" "help output contains prog name"
    assert_contains "$out" "connect" "help output lists connect command"
    assert_contains "$out" "disconnect" "help output lists disconnect command"
    assert_contains "$out" "status" "help output lists status command"
}

test_cli_version() {
    start_test "cavadvpn_cli.py version"

    local out
    out="$(python3 "$REPO_ROOT/client/cavadvpn_cli.py" version 2>&1)"
    assert_contains "$out" "CavadVPN" "version output contains app name"
}

test_cli_status_disconnected() {
    start_test "cavadvpn_cli.py status (no pidfile)"

    # Ensure no pidfile interferes
    local pid_file="$HOME/.config/cavadvpn/cavadvpn.pid"
    local backed_up=false
    if [[ -f "$pid_file" ]]; then
        mv "$pid_file" "${pid_file}.bak_test"
        backed_up=true
    fi

    local out
    out="$(python3 "$REPO_ROOT/client/cavadvpn_cli.py" status 2>&1)"
    assert_contains "$out" "DISCONNECTED" "status shows DISCONNECTED when no pidfile"

    if [[ "$backed_up" == true ]]; then
        mv "${pid_file}.bak_test" "$pid_file"
    fi
}

test_cli_config_set_get() {
    start_test "cavadvpn_cli.py config set/get"

    local tmp_cfg
    tmp_cfg="$(mktemp)"

    python3 "$REPO_ROOT/client/cavadvpn_cli.py" --config "$tmp_cfg" config --set server=10.0.0.1:443
    local out
    out="$(python3 "$REPO_ROOT/client/cavadvpn_cli.py" --config "$tmp_cfg" config 2>&1)"
    assert_contains "$out" "server" "config output has 'server' key"
    assert_contains "$out" "10.0.0.1:443" "config output has correct value"

    rm -f "$tmp_cfg"
}

# ── Test: print_summary output ────────────────────────────────────────────────
test_print_summary() {
    start_test "print_summary"

    VERSION="1.2.3"
    SIGN_IDENTITY="Developer ID: Test"

    local out
    out="$(print_summary "/tmp/CavadVPN-1.2.3.pkg")"
    assert_contains "$out" "1.2.3"         "summary shows version"
    assert_contains "$out" "CavadVPN-1.2.3.pkg" "summary shows pkg path"
    assert_contains "$out" "Developer ID"  "summary shows sign identity"
    assert_contains "$out" "installer -pkg" "summary shows install command"
}

# ── Setup: create temp repo with minimal client files ────────────────────────
setup_temp_repo() {
    _TMP_REPO="$(mktemp -d)"

    mkdir -p "$_TMP_REPO/client"
    # Create minimal stubs of each client file
    for f in core.py tun_macos.py dns.py killswitch.py reconnect.py \
              traffic_shaping.py padding.py sni_spoof.py menubar.py \
              cavadvpn_cli.py requirements.txt; do
        touch "$_TMP_REPO/client/$f"
    done
    echo "cryptography>=41.0.0" > "$_TMP_REPO/client/requirements.txt"

    # Copy real cavadvpn_cli.py so we can test it
    cp "$REPO_ROOT/client/cavadvpn_cli.py" "$_TMP_REPO/client/cavadvpn_cli.py"
}

teardown_temp_repo() {
    rm -rf "${_TMP_REPO:-}"
}

# ── Run all tests ─────────────────────────────────────────────────────────────
main() {
    echo "Running install_client.sh tests ..."
    echo ""

    setup_temp_repo

    # Source install_client.sh helpers (with main no-op)
    _source_helpers

    # Restore REPO_ROOT after sourcing (source may reset it)
    REPO_ROOT_ORIG="$REPO_ROOT"
    REPO_ROOT="$REPO_ROOT_ORIG"

    echo "--- Argument parsing ---"
    test_parse_args_defaults
    test_parse_args_flags
    test_parse_args_short_flags

    echo "--- Argument validation ---"
    test_validate_args_no_notarize
    test_validate_args_notarize_missing_fields
    test_validate_args_missing_client_dir

    echo "--- File operations ---"
    test_copy_client_files
    test_copy_scripts
    test_copy_resources

    echo "--- Log helpers ---"
    test_log_helpers

    echo "--- require_cmd ---"
    test_require_cmd_existing
    test_require_cmd_missing

    echo "--- Script syntax ---"
    test_preinstall_syntax
    test_postinstall_syntax
    test_preuninstall_syntax
    test_install_client_syntax

    echo "--- Package metadata ---"
    test_distribution_xml
    test_html_resources

    echo "--- CLI entry point ---"
    test_cli_syntax
    test_cli_help
    test_cli_version
    test_cli_status_disconnected
    test_cli_config_set_get

    echo "--- Output formatting ---"
    test_print_summary

    teardown_temp_repo
    summary
}

main "$@"
