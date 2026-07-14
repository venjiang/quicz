#!/bin/sh
set -eu

host=127.0.0.1
port=${QUICZ_PROCESS_INTEROP_PORT:-4443}
connections=${QUICZ_PROCESS_INTEROP_CONNECTIONS:-2}
max_active_connections=${QUICZ_PROCESS_INTEROP_MAX_ACTIVE_CONNECTIONS:-$connections}
mode=${QUICZ_PROCESS_INTEROP_MODE:-concurrent}
client_completion=${QUICZ_PROCESS_INTEROP_CLIENT_COMPLETION:-close}
retry=${QUICZ_PROCESS_INTEROP_RETRY:-false}
case "$mode" in
    sequential)
        server_mode=sequential
        client_parallel=false
        ;;
    concurrent)
        server_mode=concurrent
        client_parallel=true
        ;;
    rolling)
        server_mode=concurrent
        client_parallel=false
        ;;
    *)
        echo "QUICZ_PROCESS_INTEROP_MODE must be sequential, concurrent, or rolling" >&2
        exit 2
        ;;
esac
case "$retry" in
    false|0)
        client_retry=none
        ;;
    true|1)
        if [ "$mode" = sequential ]; then
            echo "Retry process interop requires concurrent or rolling mode" >&2
            exit 2
        fi
        server_mode=concurrent-retry
        client_retry=retry
        ;;
    *)
        echo "QUICZ_PROCESS_INTEROP_RETRY must be true or false" >&2
        exit 2
        ;;
esac
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

./zig-out/bin/quicz-tls13-process-echo-server "$host" "$port" "$connections" "$server_mode" "$max_active_connections" >"$server_log" 2>&1 &
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
    if [ "$client_parallel" = false ]; then
        ./zig-out/bin/quicz-tls13-process-echo-client "$host" "$port" "$client_index" "$client_completion" "$client_retry" >>"$client_log" 2>&1
    else
        ./zig-out/bin/quicz-tls13-process-echo-client "$host" "$port" "$client_index" "$client_completion" "$client_retry" >>"$client_log" 2>&1 &
        client_pids="${client_pids:-} $!"
    fi
    client_index=$((client_index + 1))
done
if [ "$client_parallel" = true ]; then
    for client_pid in $client_pids; do
        wait "$client_pid"
    done
fi
wait "$server_pid"
server_pid=

cat "$server_log"
cat "$client_log"
