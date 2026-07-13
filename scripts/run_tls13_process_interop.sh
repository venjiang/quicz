#!/bin/sh
set -eu

host=127.0.0.1
port=${QUICZ_PROCESS_INTEROP_PORT:-4443}
server_log=$(mktemp)
server_pid=

cleanup() {
    if [ -n "$server_pid" ] && kill -0 "$server_pid" 2>/dev/null; then
        kill "$server_pid" 2>/dev/null || true
    fi
    rm -f "$server_log"
}
trap cleanup EXIT HUP INT TERM

./zig-out/bin/quicz-tls13-process-echo-server "$host" "$port" >"$server_log" 2>&1 &
server_pid=$!

ready=false
attempt=0
while [ "$attempt" -lt 100 ]; do
    if grep -q "zig_process_server: listening=" "$server_log"; then
        ready=true
        break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
        cat "$server_log"
        exit 1
    fi
    sleep 0.01
    attempt=$((attempt + 1))
done
if [ "$ready" != true ]; then
    cat "$server_log"
    exit 1
fi

client_output=$(./zig-out/bin/quicz-tls13-process-echo-client "$host" "$port")
wait "$server_pid"
server_pid=

cat "$server_log"
printf '%s\n' "$client_output"
