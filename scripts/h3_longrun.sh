#!/bin/bash
# Long-run stability check for the production-runtime HTTP/3 loopback.
#
# Builds the fast example and runs it N times, requiring every run to
# complete all four rounds (GET dynamic QPACK, POST echo, GET /stream) with
# HTTP 200. Usage: scripts/h3_longrun.sh [runs] [sleep_secs]
set -euo pipefail
cd "$(dirname "$0")/.."

RUNS="${1:-50}"
SLEEP="${2:-0.4}"

"${ZIG:-zig}" build -Doptimize=fast
EXE=zig-out/bin/quicz-h3-runtime-loopback

PASS=0; FAIL=0
for i in $(seq 1 "$RUNS"); do
  out=$("$EXE" 2>&1) || true
  if echo "$out" | grep -q "OK round1=200 round2=200 echo=200 stream=200"; then
    PASS=$((PASS+1))
  else
    FAIL=$((FAIL+1))
    echo "RUN $i FAILED: $(echo "$out" | tail -1)"
  fi
  sleep "$SLEEP"
done
echo "h3_longrun: pass=$PASS fail=$FAIL runs=$RUNS"
[ "$FAIL" -eq 0 ]
