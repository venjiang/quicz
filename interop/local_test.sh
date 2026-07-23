#!/bin/bash
# Local interop test script — runs quicz interop server and client locally
# Usage: ./interop/local_test.sh [port]

set -e

PORT=${1:-4433}
CERTS_DIR="/private/tmp/certs"
WWW_DIR="/private/tmp/www"
DOWNLOADS_DIR="/private/tmp/downloads"

echo "=== quicz local interop test ==="
echo "Port: $PORT"

# Create test directories
mkdir -p "$CERTS_DIR" "$WWW_DIR" "$DOWNLOADS_DIR"

# Generate test certificate if not exists
if [ ! -f "$CERTS_DIR/cert.pem" ]; then
    echo "Generating test certificate..."
    openssl ecparam -genkey -name prime256v1 -noout -out "$CERTS_DIR/priv.key" 2>/dev/null
    openssl req -new -x509 -key "$CERTS_DIR/priv.key" -out "$CERTS_DIR/cert.pem" -days 365 -subj "/CN=localhost" 2>/dev/null
fi

# Create test files
echo "Hello QUIC interop test" > "$WWW_DIR/test.txt"
echo "Second test file for transfer" > "$WWW_DIR/transfer.txt"

# Start server
echo "Starting interop server on port $PORT..."
PORT=$PORT ./zig-out/bin/quicz-interop-server &
SERVER_PID=$!
sleep 2

# Verify server is running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "FAIL: Server failed to start"
    exit 1
fi
echo "Server started (PID $SERVER_PID)"

# Run client
echo "Running interop client..."
REQUESTS="https://localhost:$PORT/test.txt https://localhost:$PORT/transfer.txt"     ./zig-out/bin/quicz-interop-runner-client 2>&1 || true

# Cleanup
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

echo "=== Local interop test complete ==="
