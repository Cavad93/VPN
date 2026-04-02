#!/usr/bin/env bash
# install_client.sh — Build CavadVPN macOS .pkg installer
#
# Usage:
#   ./install_client.sh [OPTIONS]
#
# Options:
#   -v, --version VERSION     Package version (default: 1.0.0)
#   -o, --output-dir DIR      Output directory for .pkg (default: ./dist)
#   -r, --repo-path PATH      Path to VPN repository root (default: script's parent)
#   -s, --sign-identity ID    Developer ID Application identity for signing (optional)
#   -n, --notarize            Notarize the package after signing (requires --sign-identity)
#       --apple-id EMAIL      Apple ID for notarization
#       --apple-password PASS App-specific password for notarization
#       --team-id TEAM        Apple Developer Team ID
#   -h, --help                Show this help
#
# Requirements (macOS only):
#   - pkgbuild   (Xcode Command Line Tools)
#   - productbuild (Xcode Command Line Tools)
#   - Python 3.11+ in PATH (to verify before packaging)
#
# The resulting .pkg installs:
#   /Applications/CavadVPN/          Python client files + requirements.txt
#   /usr/local/bin/cavadvpn           CLI wrapper (created by postinstall)
#   ~/Library/LaunchAgents/com.cavadvpn.client.plist  (created by postinstall)

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$REPO_ROOT/dist"
SIGN_IDENTITY=""
NOTARIZE=false
APPLE_ID=""
APPLE_PASSWORD=""
TEAM_ID=""

# ── Helpers ───────────────────────────────────────────────────────────────────
log_info()    { echo "[INFO]    $*"; }
log_success() { echo "[SUCCESS] $*"; }
log_warn()    { echo "[WARN]    $*"; }
log_error()   { echo "[ERROR]   $*" >&2; }

die() { log_error "$*"; exit 1; }

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" &>/dev/null; then
        die "Required command not found: $cmd"
    fi
}

require_macos() {
    if [[ "$(uname -s)" != "Darwin" ]]; then
        die "This script must run on macOS (Darwin). Current OS: $(uname -s)"
    fi
}

usage() {
    grep '^#' "$0" | sed 's/^# \{0,1\}//' | tail -n +2
}

# ── Argument parsing ──────────────────────────────────────────────────────────
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -v|--version)       VERSION="$2";        shift 2 ;;
            -o|--output-dir)    OUTPUT_DIR="$2";     shift 2 ;;
            -r|--repo-path)     REPO_ROOT="$2";      shift 2 ;;
            -s|--sign-identity) SIGN_IDENTITY="$2";  shift 2 ;;
            -n|--notarize)      NOTARIZE=true;       shift   ;;
            --apple-id)         APPLE_ID="$2";       shift 2 ;;
            --apple-password)   APPLE_PASSWORD="$2"; shift 2 ;;
            --team-id)          TEAM_ID="$2";        shift 2 ;;
            -h|--help)          usage; exit 0 ;;
            *) die "Unknown option: $1" ;;
        esac
    done
}

# ── Validate args ─────────────────────────────────────────────────────────────
validate_args() {
    if [[ "$NOTARIZE" == true ]]; then
        [[ -n "$SIGN_IDENTITY" ]] || die "--notarize requires --sign-identity"
        [[ -n "$APPLE_ID"       ]] || die "--notarize requires --apple-id"
        [[ -n "$APPLE_PASSWORD" ]] || die "--notarize requires --apple-password"
        [[ -n "$TEAM_ID"        ]] || die "--notarize requires --team-id"
    fi

    if [[ ! -d "$REPO_ROOT/client" ]]; then
        die "Client directory not found: $REPO_ROOT/client"
    fi
}

# ── Prepare build directories ─────────────────────────────────────────────────
prepare_dirs() {
    BUILD_ROOT="$(mktemp -d)"
    trap 'rm -rf "$BUILD_ROOT"' EXIT

    PAYLOAD_DIR="$BUILD_ROOT/payload"
    SCRIPTS_DIR="$BUILD_ROOT/scripts"
    COMPONENT_PKG="$BUILD_ROOT/CavadVPN_component.pkg"
    RESOURCES_DIR="$BUILD_ROOT/resources"

    mkdir -p "$PAYLOAD_DIR/Applications/CavadVPN"
    mkdir -p "$SCRIPTS_DIR"
    mkdir -p "$RESOURCES_DIR"
    mkdir -p "$OUTPUT_DIR"

    log_info "Build directory: $BUILD_ROOT"
}

# ── Copy client files to payload ──────────────────────────────────────────────
copy_client_files() {
    local src="$REPO_ROOT/client"
    local dst="$PAYLOAD_DIR/Applications/CavadVPN"

    log_info "Copying client files from $src ..."

    # Python source files
    for pyfile in \
        core.py \
        tun_macos.py \
        dns.py \
        killswitch.py \
        reconnect.py \
        traffic_shaping.py \
        padding.py \
        sni_spoof.py \
        menubar.py \
        cavadvpn_cli.py \
        requirements.txt; do
        if [[ -f "$src/$pyfile" ]]; then
            cp "$src/$pyfile" "$dst/"
        else
            log_warn "Optional file not found, skipping: $pyfile"
        fi
    done

    # Menubar main entry point (symlinked to menubar.py at runtime if missing)
    if [[ ! -f "$dst/menubar_main.py" ]]; then
        cat > "$dst/menubar_main.py" <<'EOF'
#!/usr/bin/env python3
"""Menubar app entry point."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from menubar import run_menubar_app, VPNStatusModel  # type: ignore

def _connect(): pass
def _disconnect(): pass

model = VPNStatusModel()
run_menubar_app(model, _connect, _disconnect)
EOF
    fi

    log_success "Client files copied."
}

# ── Copy install scripts ───────────────────────────────────────────────────────
copy_scripts() {
    local pkg_scripts="$SCRIPT_DIR/macos_pkg/scripts"
    log_info "Copying install scripts ..."

    for script in preinstall postinstall preuninstall; do
        if [[ -f "$pkg_scripts/$script" ]]; then
            cp "$pkg_scripts/$script" "$SCRIPTS_DIR/"
            chmod +x "$SCRIPTS_DIR/$script"
        else
            die "Required script not found: $pkg_scripts/$script"
        fi
    done

    log_success "Install scripts copied."
}

# ── Copy resources (HTML pages for installer UI) ──────────────────────────────
copy_resources() {
    local pkg_res="$SCRIPT_DIR/macos_pkg/resources"
    log_info "Copying installer resources ..."

    for html in welcome.html readme.html license.html conclusion.html; do
        if [[ -f "$pkg_res/$html" ]]; then
            cp "$pkg_res/$html" "$RESOURCES_DIR/"
        else
            log_warn "Resource not found, skipping: $html"
        fi
    done

    log_success "Resources copied."
}

# ── Build component package ───────────────────────────────────────────────────
build_component_pkg() {
    log_info "Building component package with pkgbuild ..."

    local pkgbuild_args=(
        --root    "$PAYLOAD_DIR"
        --scripts "$SCRIPTS_DIR"
        --identifier "com.cavadvpn.client"
        --version "$VERSION"
        --install-location "/"
        "$COMPONENT_PKG"
    )

    if [[ -n "$SIGN_IDENTITY" ]]; then
        pkgbuild_args+=(--sign "$SIGN_IDENTITY")
    fi

    pkgbuild "${pkgbuild_args[@]}"
    log_success "Component package built: $COMPONENT_PKG"
}

# ── Build distribution package ────────────────────────────────────────────────
build_distribution_pkg() {
    local dist_xml="$SCRIPT_DIR/macos_pkg/distribution.xml"
    [[ -f "$dist_xml" ]] || die "distribution.xml not found: $dist_xml"

    # Patch version into a temp copy of distribution.xml
    local tmp_xml="$BUILD_ROOT/distribution.xml"
    sed "s/version=\"1\.0\.0\"/version=\"$VERSION\"/g" "$dist_xml" > "$tmp_xml"

    local final_pkg="$OUTPUT_DIR/CavadVPN-$VERSION.pkg"
    log_info "Building distribution package with productbuild ..."

    local productbuild_args=(
        --distribution "$tmp_xml"
        --resources    "$RESOURCES_DIR"
        --package-path "$BUILD_ROOT"
        "$final_pkg"
    )

    if [[ -n "$SIGN_IDENTITY" ]]; then
        productbuild_args+=(--sign "$SIGN_IDENTITY")
    fi

    productbuild "${productbuild_args[@]}"
    log_success "Distribution package built: $final_pkg"
    echo "$final_pkg"
}

# ── Notarize ──────────────────────────────────────────────────────────────────
notarize_pkg() {
    local pkg_path="$1"
    log_info "Submitting $pkg_path for notarization ..."

    xcrun notarytool submit "$pkg_path" \
        --apple-id       "$APPLE_ID" \
        --password       "$APPLE_PASSWORD" \
        --team-id        "$TEAM_ID" \
        --wait

    log_info "Stapling notarization ticket ..."
    xcrun stapler staple "$pkg_path"

    log_success "Notarization complete."
}

# ── Verify package ─────────────────────────────────────────────────────────────
verify_pkg() {
    local pkg_path="$1"
    log_info "Verifying package: $pkg_path ..."

    pkgutil --check-signature "$pkg_path" 2>/dev/null && \
        log_info "Signature OK" || log_warn "Package is unsigned (expected without --sign-identity)"

    log_info "Package contents:"
    pkgutil --payload-files "$pkg_path" 2>/dev/null | head -20 || true

    log_success "Package verification complete."
}

# ── Print summary ─────────────────────────────────────────────────────────────
print_summary() {
    local pkg_path="$1"
    echo ""
    echo "========================================================"
    echo "  CavadVPN macOS Installer built successfully"
    echo "========================================================"
    echo "  Package : $pkg_path"
    echo "  Version : $VERSION"
    if [[ -n "$SIGN_IDENTITY" ]]; then
        echo "  Signed  : yes ($SIGN_IDENTITY)"
    else
        echo "  Signed  : no (add --sign-identity to sign)"
    fi
    echo ""
    echo "  Install with:"
    echo "    sudo installer -pkg \"$pkg_path\" -target /"
    echo "  Or double-click the .pkg file in Finder."
    echo "========================================================"
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    parse_args "$@"

    require_macos
    require_cmd pkgbuild
    require_cmd productbuild
    validate_args
    prepare_dirs
    copy_client_files
    copy_scripts
    copy_resources
    build_component_pkg

    local final_pkg
    final_pkg="$(build_distribution_pkg)"

    if [[ "$NOTARIZE" == true ]]; then
        notarize_pkg "$final_pkg"
    fi

    verify_pkg "$final_pkg"
    print_summary "$final_pkg"
}

# Only run main when executed directly, not when sourced (e.g., by tests)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
