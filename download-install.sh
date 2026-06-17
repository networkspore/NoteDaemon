#!/usr/bin/env bash
# ============================================================
# download-install.sh — One-Shot NoteDaemon Download + Install
# ============================================================
#
# Downloads the latest NoteDaemon release tarball, builds from
# source, and runs the setup scripts.
#
# Usage:
#   sudo ./download-install.sh
#   sudo ./download-install.sh --admin-key <key>
#   sudo ./download-install.sh --admin-key <key> --noteUSB --noteAdmin
# ============================================================

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
print_status()  { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error()   { echo -e "${RED}[✗]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }

REPO_URL="https://github.com/networkspore/NoteDaemon/archive/refs/heads/master.tar.gz"
WORK_DIR="/tmp/notedaemon-install"
EXTRACTED_DIR="NoteDaemon-master"

ADMIN_KEY=""
BUILD_USB=false
BUILD_ADMIN=false

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Must run as root (use sudo)"
        exit 1
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --admin-key) ADMIN_KEY="$2"; shift 2 ;;
        --noteUSB)   BUILD_USB=true; shift ;;
        --noteAdmin) BUILD_ADMIN=true; shift ;;
        --help|-h)
            echo "Usage: sudo $0 [OPTIONS]"
            echo "  --admin-key <k>  Set admin API key"
            echo "  --noteUSB        Build + install NoteUSB module"
            echo "  --noteAdmin      Build + install note_admin CLI"
            exit 0 ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

main() {
    check_root

    echo ""
    echo "============================================"
    echo "  NoteDaemon Download + Install"
    echo "============================================"
    echo ""

    # ── 1. Install build deps ───────────────────────────────

    print_status "Installing build dependencies..."
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        build-essential cmake pkg-config \
        libusb-1.0-0-dev libssl-dev libboost-all-dev \
        wget tar
    print_success "Dependencies installed"

    # ── 2. Download ─────────────────────────────────────────

    print_status "Downloading NoteDaemon (master)..."
    rm -rf "$WORK_DIR"
    mkdir -p "$WORK_DIR"
    cd "$WORK_DIR"
    wget -q --show-progress "$REPO_URL" -O notedaemon.tar.gz
    print_success "Downloaded"

    # ── 3. Extract ──────────────────────────────────────────

    print_status "Extracting..."
    tar -xzf notedaemon.tar.gz
    cd "$EXTRACTED_DIR"
    print_success "Extracted → $WORK_DIR/$EXTRACTED_DIR"

    # ── 4. Build + Install ─────────────────────────────────

    BUILD_ARGS="--install"
    [ "$BUILD_USB" = true ] && BUILD_ARGS="$BUILD_ARGS --noteUSB"
    [ "$BUILD_ADMIN" = true ] && BUILD_ARGS="$BUILD_ARGS --noteAdmin"
    [ -n "$ADMIN_KEY" ] && BUILD_ARGS="$BUILD_ARGS --admin-key $ADMIN_KEY"

    print_status "Building + Installing..."
    print_status "Flags: $BUILD_ARGS"

    bash build.sh $BUILD_ARGS

    # ── 5. Cleanup ─────────────────────────────────────────

    echo ""
    print_status "Cleaning up..."
    cd /
    rm -rf "$WORK_DIR"
    print_success "Temp files removed"

    # ── 6. Summary ─────────────────────────────────────────

    echo ""
    echo "============================================"
    print_success "Installation Complete!"
    echo "============================================"
    echo ""
    echo "  Binary:     /etc/netnotes/note-daemon"
    echo "  Service:    note-daemon.service"
    echo "  Admin tool: /etc/netnotes/note_admin"
    echo ""
    echo "Commands:"
    echo "  systemctl status note-daemon"
    echo "  journalctl -u note-daemon -f"
    if [ -x /etc/netnotes/note_admin ]; then
        echo "  /etc/netnotes/note_admin ping"
        echo "  /etc/netnotes/note_admin list-clients"
    fi
    if [ "$BUILD_USB" = true ]; then
        echo "  ls -l /dev/hidraw*"
    fi
}

main "$@"
