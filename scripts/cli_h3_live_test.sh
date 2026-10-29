#!/bin/bash
# Live HTTP/3 verification for the quicz CLI.
#
# Proves the h3 subcommand works end to end against real online HTTP/3
# servers (QUIC handshake + HTTP/3 + QPACK), then runs a local serve -> h3
# round trip. Usage: scripts/cli_h3_live_test.sh [--skip-live]
set -euo pipefail
cd "$(dirname "$0")/.."

SKIP_LIVE=0
if [ "${1:-}" = "--skip-live" ]; then
  SKIP_LIVE=1
fi

cd cli
"${ZIG:-zig}" build

check_live() {
  local name="$1" url="$2"
  local status_file body_file
  status_file=$(mktemp)
  body_file=$(mktemp)
  if ! ./zig-out/bin/quicz h3 "$url" --timeout-ms 25000 2>"$status_file" >"$body_file"; then
    echo "FAIL: $name request failed: $(tail -1 "$status_file")" >&2
    rm -f "$status_file" "$body_file"
    return 1
  fi
  local status bytes
  status=$(sed -n 's/^HTTP\/3 //p' "$status_file" | head -1)
  bytes=$(wc -c <"$body_file" | tr -d ' ')
  rm -f "$status_file" "$body_file"
  if [ "$status" != "200" ] || [ "$bytes" -eq 0 ]; then
    echo "FAIL: $name status=$status bytes=$bytes" >&2
    return 1
  fi
  echo "PASS: $name HTTP/3 $status bytes=$bytes"
}

if [ "$SKIP_LIVE" -ne 1 ]; then
  check_live "cloudflare-quic.com" "https://cloudflare-quic.com/"
  check_live "www.fastly.com" "https://www.fastly.com/"
fi

# Local serve -> h3 round trip with the built-in loopback certificate.
dir=$(mktemp -d)
port=$((14000 + RANDOM % 2000))
printf 'hello from quicz serve\n' >"$dir/hello.txt"
./zig-out/bin/quicz serve --dir "$dir" --port "$port" --bind 127.0.0.1 >/dev/null 2>&1 &
srv=$!
trap 'kill "$srv" 2>/dev/null; wait "$srv" 2>/dev/null; rm -rf "$dir"' RETURN
sleep 1
out=$(./zig-out/bin/quicz h3 "https://127.0.0.1:$port/hello.txt" -k --timeout-ms 10000 2>&1) || true
if ! echo "$out" | grep -q "HTTP/3 200"; then
  echo "FAIL: local serve + h3 round trip: $out" >&2
  kill "$srv" 2>/dev/null
  rm -rf "$dir"
  exit 1
fi
if ! echo "$out" | grep -q "hello from quicz serve"; then
  echo "FAIL: local serve + h3 round trip body mismatch" >&2
  kill "$srv" 2>/dev/null
  rm -rf "$dir"
  exit 1
fi
echo "PASS: local serve + h3 round trip HTTP/3 200"

# /echo reflects the method and body; -d implies POST over HTTP/3.
out=$(./zig-out/bin/quicz h3 "https://127.0.0.1:$port/echo" -k -d 'a=1&b=2' --max-time 10 2>&1) || true
if ! echo "$out" | grep -q "method: POST"; then
  echo "FAIL: echo POST method: $out" >&2
  kill "$srv" 2>/dev/null
  rm -rf "$dir"
  exit 1
fi
if ! echo "$out" | grep -q "body: a=1&b=2"; then
  echo "FAIL: echo POST body: $out" >&2
  kill "$srv" 2>/dev/null
  rm -rf "$dir"
  exit 1
fi
echo "PASS: h3 -d POST echo HTTP/3 200"

# --resolve points a fake hostname at the local server.
out=$(./zig-out/bin/quicz h3 "https://local.test:$port/echo" -k --resolve "local.test:$port:127.0.0.1" --connect-timeout 5 --max-time 10 2>&1) || true
if ! echo "$out" | grep -q "authority: local.test"; then
  echo "FAIL: resolve override authority: $out" >&2
  kill "$srv" 2>/dev/null
  rm -rf "$dir"
  exit 1
fi
echo "PASS: h3 --resolve override HTTP/3 200"

# HTTPS over TCP (browser path): the same serve must answer TLS curl.
out=$(curl -skS "https://127.0.0.1:$port/hello.txt") || true
if ! echo "$out" | grep -q "hello from quicz serve"; then
  echo "FAIL: HTTPS static file: $out" >&2
  kill "$srv" 2>/dev/null
  rm -rf "$dir"
  exit 1
fi
status=$(curl -skS -o /dev/null -w '%{http_code}' "https://127.0.0.1:$port/hello.txt")
if [ "$status" != "200" ]; then
  echo "FAIL: HTTPS status=$status" >&2
  kill "$srv" 2>/dev/null
  rm -rf "$dir"
  exit 1
fi
if ! curl -skSI "https://127.0.0.1:$port/hello.txt" | grep -qi '^alt-svc:'; then
  echo "FAIL: HTTPS response missing Alt-Svc" >&2
  kill "$srv" 2>/dev/null
  rm -rf "$dir"
  exit 1
fi
echo "PASS: HTTPS browser path HTTP/1.1 200"

# OpenSSL client completes the pure-Zig TLS 1.3 handshake and gets the page.
openssl_ok=0
for _ in 1 2 3; do
  if (printf 'GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n'; sleep 1) | \
    openssl s_client -connect "127.0.0.1:$port" -servername 127.0.0.1 2>&1 | grep -q "HTTP/1.1 200 OK"; then
    openssl_ok=1
    break
  fi
  sleep 1
done
if [ "$openssl_ok" != "1" ]; then
  echo "FAIL: OpenSSL TLS interop" >&2
  kill "$srv" 2>/dev/null
  rm -rf "$dir"
  exit 1
fi
echo "PASS: OpenSSL TLS interop TLSv1.3"

kill "$srv" 2>/dev/null
wait "$srv" 2>/dev/null || true
rm -rf "$dir"
