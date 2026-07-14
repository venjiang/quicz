#!/bin/sh
set -eu

host=127.0.0.1
port=${QUICZ_PROCESS_INTEROP_PORT:-4443}
connections=${QUICZ_PROCESS_INTEROP_CONNECTIONS:-2}
mode=${QUICZ_PROCESS_INTEROP_MODE:-concurrent}
server_log=$(mktemp)
client_log=$(mktemp)
server_pid=

cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then
        cat "$server_log" >&2 || true
        cat "$client_log" >&2 || true
    fi
    if [ -n "$server_pid" ] && kill -0 "$server_pid" 2>/dev/null; then
        kill "$server_pid" 2>/dev/null || true
    fi
    rm -f "$server_log" "$client_log"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

./zig-out/bin/quicz-tls13-process-echo-server "$host" "$port" "$connections" "$mode" >"$server_log" 2>&1 &
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

client_index=0
while [ "$client_index" -lt "$connections" ]; do
    if [ "$mode" = sequential ]; then
        ./zig-out/bin/quicz-tls13-process-echo-client "$host" "$port" "$client_index" >>"$client_log" 2>&1
    else
        ./zig-out/bin/quicz-tls13-process-echo-client "$host" "$port" "$client_index" >>"$client_log" 2>&1 &
        client_pids="${client_pids:-} $!"
    fi
    client_index=$((client_index + 1))
done
if [ "$mode" != sequential ]; then
    for client_pid in $client_pids; do
        wait "$client_pid"
    done
fi
wait "$server_pid"
server_pid=

cat "$server_log"
cat "$client_log"
