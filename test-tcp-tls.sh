#!/bin/bash
# test-tcp-tls.sh - Test NoteDaemon with TCP+TLS transport
#
# This script:
# 1. Creates test TLS certificates if needed
# 2. Starts the daemon with TCP+TLS configuration
# 3. Runs the IODemo against it
# 4. Cleans up

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_DIR="/tmp/netnotes-test-certs"
DAEMON_BINARY="$SCRIPT_DIR/build/note-daemon"
TEST_PORT=9876

echo "=== NoteDaemon TCP+TLS Test ==="

# Create certificates if they don't exist
if [ ! -f "$CERT_DIR/server.crt" ]; then
    echo "[*] Creating test certificates..."
    mkdir -p "$CERT_DIR"
    cd "$CERT_DIR"
    
    # CA
    openssl genrsa -out ca.key 4096 2>/dev/null
    openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
        -subj "/CN=Netnotes Test CA" 2>/dev/null
    
    # Server
    openssl genrsa -out server.key 2048 2>/dev/null
    openssl req -new -key server.key -out server.csr \
        -subj "/CN=localhost" 2>/dev/null
    openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key \
        -CAcreateserial -out server.crt 2>/dev/null
    
    rm -f server.csr ca.srl
    echo "[✓] Test certificates created in $CERT_DIR"
fi

# Create test config
cat > "$CERT_DIR/test-config" << EOF
# TCP+TLS test configuration
socket.type=tcp
socket.bind_address=127.0.0.1
socket.listen_port=$TEST_PORT
socket.deny_unlisted=false

# TLS
tls.enabled=true
tls.cert_file=$CERT_DIR/server.crt
tls.key_file=$CERT_DIR/server.key
tls.ca_file=$CERT_DIR/ca.crt
tls.require_client_cert=false

# Logging
log.level=info
log.stderr=true

# Security
security.require_group=false

# Modules (use NoteUSB from build)
modules.directory=$SCRIPT_DIR/../NoteUSB/build
modules.strict_load=false
modules.health_check=false
EOF

echo "[*] Starting daemon with TCP+TLS on port $TEST_PORT..."
echo "    Config: $CERT_DIR/test-config"
echo "    Cert:   $CERT_DIR/server.crt"
echo ""

# Copy config to binary directory
cp "$CERT_DIR/test-config" "$SCRIPT_DIR/build/note-daemon-config"

# Start daemon in background
"$DAEMON_BINARY" &
DAEMON_PID=$!

# Wait for daemon to start
sleep 2

echo "[*] Daemon started (PID=$DAEMON_PID)"
echo ""

# Run IODemo with TLS
echo "=== Running IODemo with TLS ==="
echo ""

cd "$SCRIPT_DIR/../IODemo"
./run-features.sh --timeout 30 --tls-ca "$CERT_DIR/ca.crt" "tls://127.0.0.1:$TEST_PORT"

# Cleanup
echo ""
echo "=== Cleanup ==="
kill $DAEMON_PID 2>/dev/null || true
wait $DAEMON_PID 2>/dev/null || true
rm -f "$SCRIPT_DIR/build/note-daemon-config"
echo "[✓] Done"
