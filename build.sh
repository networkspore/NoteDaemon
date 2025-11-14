#!/usr/bin/env bash
set -e

# === CONFIGURATION ===
BUILD_DIR="build"
INSTALL=false
JOBS=$(nproc)
SERVICE_NAME="note-daemon.service"
PROJECT=NoteDaemon

# === ARGUMENTS ===
while [[ $# -gt 0 ]]; do
    case "$1" in
        --install|-i)
            INSTALL=true
            ;;
        --clean|-c)
            echo "[*] Cleaning build directory..."
            rm -rf "$BUILD_DIR"
            ;;
        --debug|-d)
            echo "[*] Building in Debug mode..."
            BUILD_TYPE="Debug"
            ;;
        --release|-r)
            echo "[*] Building in Release mode..."
            BUILD_TYPE="Release"
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--install|-i] [--clean|-c] [--debug|-d] [--release|-r]"
            exit 1
            ;;
    esac
    shift
done

# Default build type
BUILD_TYPE="${BUILD_TYPE:-Release}"

# === SETUP ===
echo "[*] Setting up build directory: $BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# === CONFIGURE ===
echo "[*] Running CMake configuration..."
cmake -DCMAKE_BUILD_TYPE="$BUILD_TYPE" ..

# === BUILD ===
echo "[*] Building $PROJECT ($BUILD_TYPE)..."
make -j"$JOBS"

# === INSTALL ===
if $INSTALL; then
    echo "[*] Installing $SERVICE_NAME system-wide (requires sudo)..."
    sudo make install

    # === RESTART SERVICE ===
    echo "[*] Restarting systemd service: $SERVICE_NAME"
    if systemctl list-units --type=service | grep -q "$SERVICE_NAME"; then
        sudo systemctl daemon-reload
        sudo systemctl restart "$SERVICE_NAME"
        sudo systemctl status "$SERVICE_NAME" --no-pager || true
        echo "[✓] $SERVICE_NAME restarted successfully!"
    else
        echo "[!] $SERVICE_NAME not found. You may need to create it manually in /etc/systemd/system/"
    fi
fi

echo "[✓] Build complete! Binary located at: $BUILD_DIR/notedaemon"
