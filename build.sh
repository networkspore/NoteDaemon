#!/usr/bin/env bash
set -e

# Get the absolute path to the script's directory at the very beginning
# This must be done before any cd commands
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NOTEUSB_DIR_ABS="$SCRIPT_DIR/../NoteUSB"

# === CONFIGURATION ===
BUILD_DIR="build"
NOTEUSB_BUILD_DIR="../NoteUSB/build"
BUILD_DIR_ABS="$SCRIPT_DIR/$BUILD_DIR"
NOTEUSB_BUILD_DIR_ABS="$NOTEUSB_DIR_ABS/build"
INSTALL=false
JOBS=$(nproc)
SERVICE_NAME="note-daemon.service"
PROJECT=NoteDaemon
NOTEUSB_PROJECT=NoteUSB
NOTEUSB_DIR="../NoteUSB"

# === ARGUMENTS ===
while [[ $# -gt 0 ]]; do
    case "$1" in
        --install|-i)
            INSTALL=true
            ;;
        --clean|-c)
            echo "[*] Cleaning build directories..."
            rm -rf "$BUILD_DIR"
            rm -rf "$NOTEUSB_DIR/build"
            ;;
        --debug|-d)
            echo "[*] Building in Debug mode..."
            BUILD_TYPE="Debug"
            ;;
        --release|-r)
            echo "[*] Building in Release mode..."
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

# Default build type
BUILD_TYPE="${BUILD_TYPE:-Release}"

# === BUILD NOTEUSB (Module) ===
if [ "$SKIP_USB" != "true" ]; then
    echo ""
    echo "========================================"
    echo "=== Building $NOTEUSB_PROJECT ==="
    echo "========================================"

    # Create NoteUSB build directory if it doesn't exist
    mkdir -p "$NOTEUSB_BUILD_DIR_ABS"
    cd "$NOTEUSB_BUILD_DIR_ABS"

    # Configure NoteUSB
    echo "[*] Running CMake configuration for $NOTEUSB_PROJECT..."
    cmake -DCMAKE_BUILD_TYPE="$BUILD_TYPE" -DBUILD_TESTS=OFF "$NOTEUSB_DIR_ABS"

    # Build NoteUSB
    echo "[*] Building $NOTEUSB_PROJECT ($BUILD_TYPE)..."
    make -j"$JOBS"

    echo "[✓] $NOTEUSB_PROJECT build complete!"
    echo "    - note_usb.so: $NOTEUSB_BUILD_DIR_ABS/note_usb.so"
    echo "    - note_usb_monitor: $NOTEUSB_BUILD_DIR_ABS/monitor/note_usb_monitor"
else
    echo "[*] Skipping NoteUSB build (--skip-usb specified)"
fi

echo ""
echo "========================================"
echo "=== Building $PROJECT ==="
echo "========================================"

# Go back to NoteDaemon directory (use the pre-calculated path)
cd "$SCRIPT_DIR"

# Create build directory if it doesn't exist
mkdir -p "$BUILD_DIR_ABS"
cd "$BUILD_DIR_ABS"

# Configure NoteDaemon
echo "[*] Running CMake configuration for $PROJECT..."
cmake -DCMAKE_BUILD_TYPE="$BUILD_TYPE" "$SCRIPT_DIR"

# Build NoteDaemon
echo "[*] Building $PROJECT ($BUILD_TYPE)..."
make -j"$JOBS"

echo "[✓] $PROJECT build complete!"
echo "    - note-daemon:    $BUILD_DIR_ABS/note-daemon"
echo "    - process-monitor: $BUILD_DIR_ABS/process-monitor/process-monitor"

# === INSTALL ===
if $INSTALL; then
    echo ""
    echo "========================================"
    echo "=== INSTALLING ==="
    echo "========================================"
    
    # Check if build directories exist
    if [ ! -f "$BUILD_DIR_ABS/note-daemon" ]; then
        echo "[!] Error: note-daemon binary not found at $BUILD_DIR_ABS/note-daemon"
        echo "[!] Build failed before install; aborting"
        exit 1
    fi
    
    if [ "$SKIP_USB" != "true" ] && [ ! -f "$NOTEUSB_BUILD_DIR_ABS/note_usb.so" ]; then
        echo "[!] Error: note_usb.so not found at $NOTEUSB_BUILD_DIR_ABS/note_usb.so"
        echo "[!] Build failed before install; aborting"
        exit 1
    fi
    
    # Note: We use manual copy commands instead of 'make install' 
    # because the CMake install targets may not be properly configured
    
    # Stop the daemon before replacing the binary
    if systemctl list-units --type=service | grep -q "$SERVICE_NAME"; then
        echo "[*] Stopping $SERVICE_NAME before upgrade..."
        sudo systemctl stop "$SERVICE_NAME" || true
        echo "[✓] $SERVICE_NAME stopped"
    fi
    
    # Create module directory
    echo "[*] Creating module directory..."
    sudo mkdir -p /etc/netnotes/modules/note_usb
    
    # Create runtime directories needed by daemon and modules
    echo "[*] Creating runtime directories..."
    sudo mkdir -p /run/netnotes
    sudo mkdir -p /run/netnotes/modules/note_usb
    sudo chmod 755 /run/netnotes
    echo "[✓] Runtime directories created"
    
    # Install NoteUSB module
    if [ "$SKIP_USB" != "true" ]; then
        echo "[*] Installing $NOTEUSB_PROJECT module to /etc/netnotes/modules/note_usb..."
        sudo cp "$NOTEUSB_BUILD_DIR_ABS/note_usb.so" /etc/netnotes/modules/note_usb/
        sudo cp "$NOTEUSB_DIR_ABS/config.json" /etc/netnotes/modules/note_usb/
        if [ -f "$NOTEUSB_BUILD_DIR_ABS/monitor/note_usb_monitor" ]; then
            sudo cp "$NOTEUSB_BUILD_DIR_ABS/monitor/note_usb_monitor" /etc/netnotes/modules/note_usb/
        fi
        echo "[✓] $NOTEUSB_PROJECT installed to /etc/netnotes/modules/note_usb/"
    fi
    
    # Install NoteDaemon
    echo "[*] Installing $PROJECT to /usr/local/bin/..."
    sudo cp "$BUILD_DIR_ABS/note-daemon" /usr/local/bin/
    if [ -f "$BUILD_DIR_ABS/process-monitor/process-monitor" ]; then
        sudo cp "$BUILD_DIR_ABS/process-monitor/process-monitor" /usr/local/bin/
    fi
    echo "[✓] $PROJECT installed to /usr/local/bin/"
    
    # === RESTART SERVICE ===
    echo "[*] Restarting systemd service: $SERVICE_NAME"
    if systemctl list-units --type=service | grep -q "$SERVICE_NAME"; then
        sudo systemctl daemon-reload
        sudo systemctl restart "$SERVICE_NAME"
        
        # Wait a moment and check status
        sleep 2
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            sudo systemctl status "$SERVICE_NAME" --no-pager || true
            echo "[✓] $SERVICE_NAME restarted successfully!"
        else
            echo "[!] $SERVICE_NAME failed to start. Check logs with: sudo journalctl -u $SERVICE_NAME -n 50"
            sudo journalctl -u "$SERVICE_NAME" -n 50 || true
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

if [ "$SKIP_USB" != "true" ]; then
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
    echo "    - note_usb.so -> /etc/netnotes/modules/note_usb/note_usb.so"
    echo "    - note_usb_monitor -> /etc/netnotes/modules/note_usb/note_usb_monitor"
    echo "    - config.json -> /etc/netnotes/modules/note_usb/config.json"
fi
