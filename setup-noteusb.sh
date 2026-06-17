#!/usr/bin/env bash
# ============================================================
# setup-noteusb.sh — NoteUSB Module Setup
# ============================================================
#
# Sets up USB device support for NoteDaemon:
#   - udev rules (99-netnotes.rules)
#   - USB module install (note_usb.so)
#   - USB monitor (note_usb_monitor)
#   - Device permissions (hidraw, usb)
#   - User group membership for USB access
#
# Prerequisites: setup-netnotes.sh must be run first
#
# Usage:
#   sudo ./setup-noteusb.sh                     # Interactive
#   sudo ./setup-noteusb.sh --auto              # Non-interactive
#   sudo ./setup-noteusb.sh --add-user <name>   # Add user to netnotes group
# ============================================================

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
print_status()  { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error()   { echo -e "${RED}[✗]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}
get_sudo_user() {
    [[ -n "$SUDO_USER" ]] && echo "$SUDO_USER" || echo "$USER"
}
prompt_yes_no() {
    local prompt="$1" default="${2:-Y}" response
    if [[ "$default" == "Y" ]]; then
        read -p "$prompt [Y/n]: " response; response=${response:-Y}
    else
        read -p "$prompt [y/N]: " response; response=${response:-N}
    fi
    [[ "$response" =~ ^[Yy]$ ]]
}

# ── Flags ──────────────────────────────────────────────────────
AUTO_MODE=false
FORCE_MODE=false
ADD_USER=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --auto)      AUTO_MODE=true; shift ;;
        --force|-f)  FORCE_MODE=true; shift ;;
        --add-user)  ADD_USER="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: sudo $0 [OPTIONS]"
            echo "  --auto          Non-interactive"
            echo "  --force, -f     Re-configure"
            echo "  --add-user <u>  Add user to netnotes group"
            exit 0 ;;
        *) shift ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
UDEV_RULES_SRC="$SCRIPT_DIR/99-netnotes.rules"
UDEV_RULES_DST="/etc/udev/rules.d/99-netnotes.rules"
USB_SO_SRC="$SCRIPT_DIR/../NoteUSB/build/note_usb.so"
USB_MONITOR_SRC="$SCRIPT_DIR/../NoteUSB/build/monitor/note_usb_monitor"
USB_CONFIG_SRC="$SCRIPT_DIR/../NoteUSB/config.json"
USB_MODULE_DIR="/etc/netnotes/modules/note_usb"

# ── Already set up? ────────────────────────────────────────────

check_already_setup() {
    [ -f "$UDEV_RULES_DST" ] || return 1
    [ -f "$USB_MODULE_DIR/note_usb.so" ] || return 1
    return 0
}

# ── Main ───────────────────────────────────────────────────────

main() {
    check_root
    CALLING_USER=$(get_sudo_user)

    if [ "$FORCE_MODE" = false ] && check_already_setup; then
        if [ "$AUTO_MODE" = true ]; then
            echo "[noteusb] Already configured — skipping (use --force to re-run)"
            return 0
        fi
        print_warning "NoteUSB appears already set up."
        if ! prompt_yes_no "Re-configure?" "N"; then
            return 0
        fi
    fi

    echo ""
    echo "============================================"
    echo "  NoteUSB Module Setup"
    echo "============================================"
    echo ""

    # ── 1. Verify core daemon is installed ──────────────────

    if [ ! -f /etc/netnotes/note-daemon ]; then
        print_error "Core NoteDaemon not found at /etc/netnotes/note-daemon"
        print_error "Run setup-netnotes.sh first"
        exit 1
    fi
    print_status "Core daemon: installed"

    if ! getent group netnotes >/dev/null; then
        print_error "netnotes group not found — run setup-netnotes.sh first"
        exit 1
    fi

    # ── 2. udev rules ──────────────────────────────────────

    echo ""
    if [ -f "$UDEV_RULES_SRC" ]; then
        print_status "Installing udev rules..."
        cp "$UDEV_RULES_SRC" "$UDEV_RULES_DST"
        chmod 0644 "$UDEV_RULES_DST"
        print_success "udev rules → $UDEV_RULES_DST"

        print_status "Reloading udev..."
        udevadm control --reload-rules
        udevadm trigger
        print_success "udev reloaded"
    else
        print_warning "udev rules not found: $UDEV_RULES_SRC"
    fi

    # ── 3. USB module ──────────────────────────────────────

    echo ""
    if [ -f "$USB_SO_SRC" ]; then
        print_status "Installing NoteUSB module..."
        mkdir -p "$USB_MODULE_DIR"
        cp "$USB_SO_SRC" "$USB_MODULE_DIR/note_usb.so"
        chmod 0755 "$USB_MODULE_DIR/note_usb.so"

        if [ -f "$USB_CONFIG_SRC" ]; then
            cp "$USB_CONFIG_SRC" "$USB_MODULE_DIR/config.json"
        fi
        if [ -f "$USB_MONITOR_SRC" ]; then
            cp "$USB_MONITOR_SRC" "$USB_MODULE_DIR/note_usb_monitor"
            chmod 0755 "$USB_MODULE_DIR/note_usb_monitor"
        fi

        chown -R root:netnotes "$USB_MODULE_DIR"
        print_success "NoteUSB module installed → $USB_MODULE_DIR"
    else
        if [ "$AUTO_MODE" = true ]; then
            print_warning "NoteUSB .so not built — skipping module install"
            print_status "Build: cd ../NoteUSB/build && cmake .. && make"
        elif prompt_yes_no "NoteUSB module not found. Build it now?" "Y"; then
            local usb_dir="$SCRIPT_DIR/../NoteUSB"
            if [ -f "$usb_dir/CMakeLists.txt" ]; then
                mkdir -p "$usb_dir/build"
                cd "$usb_dir/build"
                cmake -DCMAKE_BUILD_TYPE=Release "$usb_dir" > /dev/null
                make -j$(nproc)
                cd "$SCRIPT_DIR"

                # Retry install
                USB_SO_SRC="$usb_dir/build/note_usb.so"
                if [ -f "$USB_SO_SRC" ]; then
                    mkdir -p "$USB_MODULE_DIR"
                    cp "$USB_SO_SRC" "$USB_MODULE_DIR/note_usb.so"
                    chmod 0755 "$USB_MODULE_DIR/note_usb.so"
                    chown -R root:netnotes "$USB_MODULE_DIR"
                    print_success "NoteUSB module built + installed"
                else
                    print_error "Build failed"
                fi
            else
                print_error "NoteUSB source not found at $usb_dir"
            fi
        fi
    fi

    # ── 4. Group membership ────────────────────────────────

    echo ""
    echo "============================================"
    print_status "USB Access — Group Membership"
    echo "============================================"
    echo ""
    print_status "Users in 'netnotes' group can access USB devices."
    echo ""

    # Add calling user
    if [ "$CALLING_USER" != "root" ]; then
        if groups "$CALLING_USER" 2>/dev/null | grep -q netnotes; then
            print_status "User '$CALLING_USER' already in netnotes group"
        elif [ "$AUTO_MODE" = true ] || prompt_yes_no "Add '$CALLING_USER' to netnotes group?" "Y"; then
            usermod -a -G netnotes "$CALLING_USER"
            print_success "Added '$CALLING_USER' to netnotes group"
            print_warning "Log out and back in for group to take effect"
        fi
    fi

    # Add user from --add-user flag
    if [ -n "$ADD_USER" ]; then
        if id "$ADD_USER" >/dev/null 2>&1; then
            usermod -a -G netnotes "$ADD_USER" 2>/dev/null && \
                print_success "Added '$ADD_USER' to netnotes group" || \
                print_warning "'$ADD_USER' may already be in the group"
        else
            print_error "User '$ADD_USER' does not exist"
        fi
    fi

    # Offer to add another user
    if [ "$AUTO_MODE" = false ]; then
        if prompt_yes_no "Add another user to netnotes group?" "N"; then
            read -p "Username: " username
            if [ -n "$username" ] && id "$username" >/dev/null 2>&1; then
                usermod -a -G netnotes "$username"
                print_success "Added '$username' to netnotes group"
            elif [ -n "$username" ]; then
                print_error "User '$username' does not exist"
            fi
        fi
    fi

    # ── 5. Device permissions ──────────────────────────────

    echo ""
    if [ "$AUTO_MODE" = true ] || prompt_yes_no "Show USB device permissions?" "N"; then
        echo ""
        print_status "USB devices:"
        ls -l /dev/bus/usb/*/* 2>/dev/null | head -10 || echo "  (none)"
        echo ""
        print_status "HID devices:"
        ls -l /dev/hidraw* 2>/dev/null | head -10 || echo "  (none)"
    fi

    # ── Summary ─────────────────────────────────────────────

    echo ""
    echo "============================================"
    print_success "NoteUSB Setup Complete"
    echo "============================================"
    echo ""
    echo "  udev rules:  $UDEV_RULES_DST"
    echo "  Module:      $USB_MODULE_DIR/note_usb.so"
    echo "  Group:       netnotes (for USB device access)"
    echo ""
    echo "Restart NoteDaemon to load the module:"
    echo "  sudo systemctl restart note-daemon"
}

main "$@"
