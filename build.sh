#!/usr/bin/env bash
set -e

# Script directory (absolute)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# === CONFIGURATION ===
BUILD_TYPE="${BUILD_TYPE:-Release}"
BUILD_DIR="build"
NOTEUSB_DIR="../NoteUSB"
NOTEUSB_BUILD_DIR="../NoteUSB/build"

BUILD_DIR_ABS="$SCRIPT_DIR/$BUILD_DIR"
NOTEUSB_DIR_ABS="$SCRIPT_DIR/$NOTEUSB_DIR"
NOTEUSB_BUILD_DIR_ABS="$NOTEUSB_DIR_ABS/$NOTEUSB_BUILD_DIR"

INSTALL=false
SKIP_USB=false
CLEAN=false
JOBS=$(nproc)

SERVICE_NAME="note-daemon.service"

# When run via sudo, use the original user for build directories
# so they remain usable by that user (and assistant tooling) without sudo.
if [ "$(id -u)" -eq 0 ] && [ -n "$SUDO_USER" ]; then
    BUILD_USER="$SUDO_USER"
    BUILD_UID="${SUDO_UID:-$(id -u "$SUDO_USER")}"
    BUILD_GID="${SUDO_GID:-$(id -g "$SUDO_USER")}"
else
    BUILD_USER="$(whoami)"
    BUILD_UID="$(id -u)"
    BUILD_GID="$(id -g)"
fi

echo "[*] Build user: $BUILD_USER (uid=$BUILD_UID gid=$BUILD_GID)"

run_as_build_user() {
    if [ "$(id -u)" -eq 0 ] && [ -n "$SUDO_USER" ] && [ "$BUILD_USER" != "root" ]; then
        if command -v sudo >/dev/null 2>&1; then
            sudo -H -u "$BUILD_USER" "$@"
            return
        fi
        if command -v runuser >/dev/null 2>&1; then
            runuser -u "$BUILD_USER" -- "$@"
            return
        fi
        echo "[!] Cannot switch to build user '$BUILD_USER' (sudo/runuser not found)."
        exit 1
    fi
    "$@"
}

fix_build_ownership() {
    if [ "$(id -u)" -eq 0 ]; then
        chown -R "$BUILD_UID:$BUILD_GID" "$1"
    fi
}

# === ARGUMENTS ===
while [[ $# -gt 0 ]]; do
    case "$1" in
        --install|-i)
            INSTALL=true
            ;;
        --clean|-c)
            CLEAN=true
            ;;
        --debug|-d)
            BUILD_TYPE="Debug"
            ;;
        --release|-r)
            BUILD_TYPE="Release"
            ;;
        --skip-usb)
            SKIP_USB=true
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--install|-i] [--clean|-c] [--debug|-d] [--release|-r] [--skip-usb]"
            exit 1
            ;;
    esac
    shift
done

# === CLEAN (if requested) ===
if [ "$CLEAN" = true ]; then
    echo "[*] Cleaning build directories..."
    rm -rf "$BUILD_DIR_ABS"
    rm -rf "$NOTEUSB_BUILD_DIR_ABS"
    echo "[✓] Clean complete"
fi

# === BUILD NOTEUSB (Module) ===
if [ "$SKIP_USB" = false ]; then
    echo ""
    echo "========================================"
    echo "=== Building NoteUSB ==="
    echo "========================================"

    mkdir -p "$NOTEUSB_BUILD_DIR_ABS"
    fix_build_ownership "$NOTEUSB_BUILD_DIR_ABS"
    chmod -R u+rwX,go+rX "$NOTEUSB_BUILD_DIR_ABS"

    run_as_build_user bash -lc "
        cd '$NOTEUSB_BUILD_DIR_ABS'
        echo '[*] Configuring NoteUSB (CMake)...'
        cmake -DCMAKE_BUILD_TYPE='$BUILD_TYPE' -DBUILD_TESTS=OFF '$NOTEUSB_DIR_ABS'
        echo '[*] Building NoteUSB ($BUILD_TYPE)...'
        make -j'$JOBS'
    "
    fix_build_ownership "$NOTEUSB_BUILD_DIR_ABS"

    echo "[✓] NoteUSB build complete!"
    echo "    - note_usb.so: $NOTEUSB_BUILD_DIR_ABS/note_usb.so"
    echo "    - note_usb_monitor: $NOTEUSB_BUILD_DIR_ABS/monitor/note_usb_monitor"
else
    echo "[*] Skipping NoteUSB build (--skip-usb specified)"
fi

# === BUILD NOTEDEAMON ===
echo ""
echo "========================================"
echo "=== Building NoteDaemon ==="
echo "========================================"

mkdir -p "$BUILD_DIR_ABS"
fix_build_ownership "$BUILD_DIR_ABS"
chmod -R u+rwX,go+rX "$BUILD_DIR_ABS"

run_as_build_user bash -lc "
    cd '$BUILD_DIR_ABS'
    echo '[*] Configuring NoteDaemon (CMake)...'
    cmake -DCMAKE_BUILD_TYPE='$BUILD_TYPE' '$SCRIPT_DIR'
    echo '[*] Building NoteDaemon ($BUILD_TYPE)...'
    make -j'$JOBS'
"
fix_build_ownership "$BUILD_DIR_ABS"

echo "[✓] NoteDaemon build complete!"
echo "    - note-daemon:    $BUILD_DIR_ABS/note-daemon"
echo "    - process-monitor: $BUILD_DIR_ABS/process-monitor/process-monitor"

# === INSTALL (requires elevation) ===
if [ "$INSTALL" = true ]; then
    echo ""
    echo "========================================"
    echo "=== INSTALLING (requires authentication) ==="
    echo "========================================"

    # Validate build outputs
    if [ ! -f "$BUILD_DIR_ABS/note-daemon" ]; then
        echo "[!] Error: note-daemon binary not found at $BUILD_DIR_ABS/note-daemon"
        echo "[!] Build failed before install; aborting"
        exit 1
    fi

    if [ "$SKIP_USB" = false ] && [ ! -f "$NOTEUSB_BUILD_DIR_ABS/note_usb.so" ]; then
        echo "[!] Error: note_usb.so not found at $NOTEUSB_BUILD_DIR_ABS/note_usb.so"
        echo "[!] Build failed before install; aborting"
        exit 1
    fi

    # Choose elevation command: prefer pkexec if available, else sudo
    if command -v pkexec >/dev/null 2>&1; then
        ELEV="pkexec"
    elif command -v sudo >/dev/null 2>&1; then
        ELEV="sudo"
    else
        echo "[!] Neither pkexec nor sudo found; cannot install with elevated privileges."
        exit 1
    fi

    # Stop the daemon before replacing files
    if systemctl list-units --type=service | grep -q "$SERVICE_NAME"; then
        echo "[*] Stopping $SERVICE_NAME before upgrade..."
        $ELEV systemctl stop "$SERVICE_NAME" || true
        echo "[✓] $SERVICE_NAME stopped"
    fi

    # Install NoteDaemon binary
    echo "[*] Installing NoteDaemon to /usr/local/bin/..."
    $ELEV cp "$BUILD_DIR_ABS/note-daemon" /usr/local/bin/
    if [ -f "$BUILD_DIR_ABS/process-monitor/process-monitor" ]; then
        $ELEV cp "$BUILD_DIR_ABS/process-monitor/process-monitor" /usr/local/bin/
    fi
    echo "[✓] NoteDaemon installed"

    # Install default config next to the binary
    DEFAULT_CONFIG="$SCRIPT_DIR/config.default"
    if [ -f "$DEFAULT_CONFIG" ]; then
        echo "[*] Installing config to /usr/local/bin/note-daemon-config"
        $ELEV cp "$DEFAULT_CONFIG" /usr/local/bin/note-daemon-config
        $ELEV chmod 644 /usr/local/bin/note-daemon-config
        echo "[✓] Config installed"
    else
        echo "[!] Warning: config.default not found in NoteDaemon; skipping config install"
    fi

    # Create modules directory next to the binary
    echo "[*] Creating modules directory at /usr/local/bin/modules..."
    $ELEV mkdir -p /usr/local/bin/modules/note_usb
    $ELEV chmod -R 755 /usr/local/bin/modules
    echo "[✓] Modules directory created"

    # Install NoteUSB module
    if [ "$SKIP_USB" = false ]; then
        echo "[*] Installing NoteUSB module to /usr/local/bin/modules/note_usb..."
        $ELEV cp "$NOTEUSB_BUILD_DIR_ABS/note_usb.so" /usr/local/bin/modules/note_usb/
        $ELEV cp "$NOTEUSB_DIR_ABS/config.json" /usr/local/bin/modules/note_usb/
        if [ -f "$NOTEUSB_BUILD_DIR_ABS/monitor/note_usb_monitor" ]; then
            $ELEV cp "$NOTEUSB_BUILD_DIR_ABS/monitor/note_usb_monitor" /usr/local/bin/modules/note_usb/
        fi
        echo "[✓] NoteUSB installed"
    fi

    # Create root and subdirectories under /etc/netnotes
    echo "[*] Preparing /etc/netnotes directories..."
    $ELEV mkdir -p /etc/netnotes/runtime
    $ELEV mkdir -p /etc/netnotes/logs
    $ELEV mkdir -p /etc/netnotes/note_usb/device_registry
    $ELEV chmod -R 755 /etc/netnotes
    echo "[✓] /etc/netnotes directories created"

    # Ensure runtime directory /run/netnotes for socket and module runtime dirs
    echo "[*] Ensuring runtime directory /run/netnotes..."
    $ELEV mkdir -p /run/netnotes
    $ELEV chown root:netnotes /run/netnotes
    $ELEV chmod 775 /run/netnotes

    # Directory for NoteUSB runtime files
    $ELEV mkdir -p /run/netnotes/modules/note_usb
    $ELEV chown -R root:netnotes /run/netnotes/modules/note_usb
    $ELEV chmod -R 775 /run/netnotes/modules/note_usb
    echo "[✓] Runtime directory ready"

    # Restart service
    echo "[*] Restarting systemd service: $SERVICE_NAME"
    if systemctl list-units --type=service | grep -q "$SERVICE_NAME"; then
        $ELEV systemctl daemon-reload
        $ELEV systemctl restart "$SERVICE_NAME"

        sleep 2
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            $ELEV systemctl status "$SERVICE_NAME" --no-pager || true
            echo "[✓] $SERVICE_NAME restarted successfully!"
        else
            echo "[!] $SERVICE_NAME failed to start. Check logs with:"
            echo "    $ELEV journalctl -u $SERVICE_NAME -n 50"
            $ELEV journalctl -u "$SERVICE_NAME" -n 50 || true
        fi
    else
        echo "[!] $SERVICE_NAME not found. You may need to create it manually in /etc/systemd/system/"
    fi
fi

echo ""
echo "========================================"
echo "=== BUILD SUMMARY ==="
echo "========================================"
echo "[✓] NoteDaemon binary: $BUILD_DIR_ABS/note-daemon"
echo "[✓] process-monitor: $BUILD_DIR_ABS/process-monitor/process-monitor"

if [ "$SKIP_USB" = false ]; then
    if [ -d "$NOTEUSB_BUILD_DIR_ABS" ]; then
        echo "[✓] note_usb.so: $NOTEUSB_BUILD_DIR_ABS/note_usb.so"
        echo "[✓] note_usb_monitor: $NOTEUSB_BUILD_DIR_ABS/monitor/note_usb_monitor"
    else
        echo "[✓] note_usb.so: (not built)"
        echo "[✓] note_usb_monitor: (not built)"
    fi
    echo ""
    echo "=== INSTALL PATHS (for reference) ==="
    echo "    - note-daemon -> /usr/local/bin/note-daemon"
    echo "    - config -> /usr/local/bin/note-daemon-config (from ../config.default)"
    echo "    - modules -> /usr/local/bin/modules/note_usb/note_usb.so"
fi
