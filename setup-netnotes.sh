#!/usr/bin/env bash
# ============================================================
# setup-netnotes.sh — Core NoteDaemon Setup
# ============================================================
#
# Sets up ONLY the core daemon:
#   - System user/group (netnotes)
#   - Runtime + data directories
#   - Binary install (note-daemon, process-monitor, note_admin)
#   - systemd service
#   - Admin API key (via note_admin)
#
# For USB udev rules and device setup, see setup-noteusb.sh
# For remote/display setup, see setup-noteremote.sh
#
# Usage:
#   sudo ./setup-netnotes.sh                        # Interactive
#   sudo ./setup-netnotes.sh --auto                 # Non-interactive, skip if done
#   sudo ./setup-netnotes.sh --force                # Re-run even if configured
#   sudo ./setup-netnotes.sh --auto --admin-key <k>  # Auto + admin key
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
ADMIN_KEY=""
SKIP_BUILD=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --auto)        AUTO_MODE=true; shift ;;
        --force|-f)    FORCE_MODE=true; shift ;;
        --admin-key)   ADMIN_KEY="$2"; shift 2 ;;
        --skip-build)  SKIP_BUILD=true; shift ;;
        --help|-h)
            echo "Usage: sudo $0 [OPTIONS]"
            echo "  --auto           Non-interactive, skip if already configured"
            echo "  --force, -f      Re-configure even if already set up"
            echo "  --admin-key <k>  Set admin API key (requires note_admin)"
            echo "  --skip-build     Don't build (use existing build/ binaries)"
            exit 0 ;;
        *) shift ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY_SRC="$SCRIPT_DIR/build/note-daemon"
MONITOR_SRC="$SCRIPT_DIR/build/process-monitor/process-monitor"
ADMIN_SRC="$SCRIPT_DIR/tools/note_admin.c"
ADMIN_BIN="$SCRIPT_DIR/build/note_admin"
BINARY_DST="/etc/netnotes/note-daemon"
MONITOR_DST="/etc/netnotes/process-monitor"
ADMIN_DST="/etc/netnotes/note_admin"
SERVICE_FILE="$SCRIPT_DIR/note-daemon.service"
SERVICE_DST="/etc/systemd/system/note-daemon.service"
SERVICE_NAME="note-daemon.service"

# ── Already set up? ────────────────────────────────────────────

check_already_setup() {
    [ -f "$BINARY_DST" ] || return 1
    [ -f "$SERVICE_DST" ] || return 1
    systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null || return 1
    return 0
}

# ── Main ───────────────────────────────────────────────────────

main() {
    check_root
    CALLING_USER=$(get_sudo_user)

    # Check if already done (skip in auto mode, warn in interactive)
    if [ "$FORCE_MODE" = false ] && check_already_setup; then
        if [ "$AUTO_MODE" = true ]; then
            echo "[note-daemon] Already configured — skipping (use --force to re-run)"
            return 0
        fi
        print_warning "NoteDaemon appears to be already set up."
        if ! prompt_yes_no "Re-configure?" "N"; then
            print_status "Skipping setup."
            return 0
        fi
    fi

    echo ""
    echo "============================================"
    echo "  NoteDaemon Core Setup"
    echo "============================================"
    echo ""
    print_status "Setup initiated by: $CALLING_USER"
    [ "$FORCE_MODE" = true ] && print_warning "FORCE mode — re-configuring"

    # ── 1. Build (if not skipped) ────────────────────────────

    if [ "$SKIP_BUILD" = false ] && [ "$AUTO_MODE" = false ]; then
        if prompt_yes_no "Build NoteDaemon from source?" "Y"; then
            if [ ! -f "$SCRIPT_DIR/CMakeLists.txt" ]; then
                print_error "CMakeLists.txt not found. Run from the NoteDaemon project root."
                exit 1
            fi
            mkdir -p "$SCRIPT_DIR/build"
            cd "$SCRIPT_DIR/build"
            print_status "Running CMake..."
            cmake -DCMAKE_BUILD_TYPE=Release "$SCRIPT_DIR" > /dev/null
            print_status "Compiling ($(nproc) cores)..."
            make -j$(nproc)
            print_success "Build complete"
            cd "$SCRIPT_DIR"
        fi
    fi

    if [ ! -f "$BINARY_SRC" ]; then
        print_error "note-daemon not found at $BINARY_SRC"
        print_error "Build first: cd build && cmake .. && make"
        exit 1
    fi

    # ── 2. User + group ─────────────────────────────────────

    echo ""
    if [ "$AUTO_MODE" = true ] || prompt_yes_no "Create netnotes system user/group?" "Y"; then
        if ! getent group netnotes >/dev/null; then
            groupadd --system netnotes
            print_success "Created netnotes group"
        else
            print_warning "netnotes group already exists"
        fi
        if ! id netnotes >/dev/null 2>&1; then
            useradd --system --no-create-home --home-dir /var/lib/netnotes \
                    -g netnotes --shell /usr/sbin/nologin netnotes
            print_success "Created netnotes user"
        else
            print_warning "netnotes user already exists"
        fi
    fi

    # ── 3. Directories ──────────────────────────────────────

    echo ""
    print_status "Creating runtime directories..."
    mkdir -p /var/lib/netnotes /run/netnotes /etc/netnotes/modules
    chown -R netnotes:netnotes /var/lib/netnotes /run/netnotes /etc/netnotes 2>/dev/null || true
    chmod 0750 /var/lib/netnotes /run/netnotes
    print_success "Directories ready"

    # ── 4. Install binaries ─────────────────────────────────

    echo ""
    print_status "Installing binaries..."
    install -m 0755 -o root -g netnotes "$BINARY_SRC" "$BINARY_DST"
    print_success "note-daemon → $BINARY_DST"

    if [ -f "$MONITOR_SRC" ]; then
        install -m 0755 -o root -g netnotes "$MONITOR_SRC" "$MONITOR_DST"
        print_success "process-monitor → $MONITOR_DST"
    fi

    # Compile and install note_admin
    if [ -f "$ADMIN_SRC" ]; then
        print_status "Compiling note_admin..."
        if gcc -o "$ADMIN_BIN" "$ADMIN_SRC" -Wall -Wno-unused 2>/dev/null; then
            install -m 0755 -o root -g netnotes "$ADMIN_BIN" "$ADMIN_DST"
            print_success "note_admin → $ADMIN_DST"
        else
            print_warning "note_admin compilation failed (non-critical)"
        fi
    fi

    # ── 5. systemd service ──────────────────────────────────

    echo ""
    if [ -f "$SERVICE_FILE" ]; then
        print_status "Installing systemd service..."
        cp "$SERVICE_FILE" "$SERVICE_DST"
        chmod 0644 "$SERVICE_DST"
        systemctl daemon-reload
        print_success "Service installed"

        if [ "$AUTO_MODE" = true ] || prompt_yes_no "Enable and start service?" "Y"; then
            systemctl enable "$SERVICE_NAME" 2>/dev/null || true
            systemctl restart "$SERVICE_NAME" 2>/dev/null || systemctl start "$SERVICE_NAME"
            sleep 2
            if systemctl is-active --quiet "$SERVICE_NAME"; then
                print_success "Service running"
            else
                print_error "Service failed to start"
                systemctl status "$SERVICE_NAME" --no-pager -l || true
            fi
        fi
    else
        print_warning "Service file not found: $SERVICE_FILE"
    fi

    # ── 6. Admin key ────────────────────────────────────────

    echo ""
    echo "============================================"
    print_status "Admin API Key"
    echo "============================================"
    echo ""

    NOTE_ADMIN=""
    [ -x "$ADMIN_DST" ] && NOTE_ADMIN="$ADMIN_DST"
    [ -x "$ADMIN_BIN" ] && NOTE_ADMIN="$ADMIN_BIN"

    if [ -z "$NOTE_ADMIN" ]; then
        print_warning "note_admin not found — admin key setup unavailable"
        print_status "Compile: gcc -o tools/note_admin tools/note_admin.c"
    elif [ -n "$ADMIN_KEY" ]; then
        print_status "Setting admin API key (from --admin-key)..."
        if "$NOTE_ADMIN" setup "$ADMIN_KEY"; then
            print_success "Admin key configured"
            print_success "dnd-server client created (api_key: sk-dnd-server-001)"

            # Store key
            mkdir -p /root/.config/netnotes
            echo "$ADMIN_KEY" > /root/.config/netnotes/admin_key
            chmod 600 /root/.config/netnotes/admin_key
            if [ "$CALLING_USER" != "root" ]; then
                local uh; uh=$(eval echo ~"$CALLING_USER")
                mkdir -p "$uh/.config/netnotes"
                echo "$ADMIN_KEY" > "$uh/.config/netnotes/admin_key"
                chown "$CALLING_USER:$CALLING_USER" "$uh/.config/netnotes/admin_key" 2>/dev/null || true
                chmod 600 "$uh/.config/netnotes/admin_key"
            fi
        else
            print_error "Admin key setup failed"
        fi
    elif [ "$AUTO_MODE" = true ]; then
        print_warning "No --admin-key provided — skipping"
        print_status "Set later: sudo $ADMIN_DST setup <your-key>"
    elif prompt_yes_no "Configure admin API key now?" "Y"; then
        read -s -p "Admin API key: " input_key
        echo ""
        if [ -n "$input_key" ]; then
            read -s -p "Confirm: " confirm_key
            echo ""
            if [ "$input_key" = "$confirm_key" ]; then
                if "$NOTE_ADMIN" setup "$input_key"; then
                    print_success "Admin key configured"
                    mkdir -p /root/.config/netnotes
                    echo "$input_key" > /root/.config/netnotes/admin_key
                    chmod 600 /root/.config/netnotes/admin_key
                else
                    print_error "Setup failed"
                fi
            else
                print_error "Keys don't match"
            fi
        fi
    fi

    # ── Summary ─────────────────────────────────────────────

    echo ""
    echo "============================================"
    print_success "Core Setup Complete"
    echo "============================================"
    echo ""
    echo "  Binary:     $BINARY_DST"
    echo "  Service:    $SERVICE_NAME"
    echo "  Admin tool: $ADMIN_DST"
    echo "  Socket:     /run/netnotes/notedaemon.sock"
    echo ""
    echo "Commands:"
    echo "  Status:     systemctl status note-daemon"
    echo "  Logs:       journalctl -u note-daemon -f"
    echo "  Ping:       $ADMIN_DST ping"
    echo "  Admin:      $ADMIN_DST setup <key>"
    echo ""
    echo "For USB device support: sudo ./setup-noteusb.sh"
}

main "$@"
