#!/bin/bash
# quicz benchmark suite — standardized baseline recording.
#
# Builds every benchmark (fast), runs them in a fixed order, and
# records platform metadata, commit, and full per-benchmark output under
# bench_results/<UTC timestamp>_<commit>.log. Committed result files are
# the comparable performance baseline; re-run after changes and diff.
#
# Usage: scripts/run_bench_suite.sh
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
cd "$ROOT"

COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo nogit)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="$ROOT/bench_results"
mkdir -p "$OUT_DIR"
LOG="$OUT_DIR/${STAMP}_${COMMIT}.log"

{
    echo "# quicz benchmark suite"
    echo "# commit: $(git rev-parse HEAD 2>/dev/null || echo nogit)"
    echo "# date_utc: $STAMP"
    echo "# os: $(uname -sm)"
    echo "# cpu: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m)"
    echo "# zig: $("${ZIG:-zig}" version)"
    echo "# optimize: fast (bench modules force it in build.zig)"
} > "$LOG"
cat "$LOG"

echo ""
echo "building all benchmarks (fast)..."
if ! "${ZIG:-zig}" build -Doptimize=fast --global-cache-dir .zig-cache/global; then
    echo "build failed" | tee -a "$LOG"
    exit 1
fi

# Fixed order: micro-benchmark first, then real-handshake, raw processing,
# DATAGRAM, per-phase profile, congestion comparison.
BENCHES=(
    "quicz-quic-bench:installed-keys micro-benchmark (throughput + latency)"
    "quicz-quic-bench-hs:real-handshake throughput + latency"
    "quicz-quic-bench-simple:single-threaded raw QUIC processing"
    "quicz-quic-bench-datagram:RFC 9221 DATAGRAM throughput"
    "quicz-quic-bench-profile:per-phase profiling"
    "quicz-congestion-bench:NewReno vs CUBIC simulated loss"
)

FAILURES=0
for entry in "${BENCHES[@]}"; do
    BIN="${entry%%:*}"
    DESC="${entry#*:}"
    echo "" | tee -a "$LOG"
    echo "=== $BIN ($DESC) ===" | tee -a "$LOG"
    "$ROOT/zig-out/bin/$BIN" 2>&1 | tee -a "$LOG"
    RC=${PIPESTATUS[0]}
    if [ "$RC" -eq 0 ]; then
        echo "[suite] $BIN: PASS" | tee -a "$LOG"
    else
        echo "[suite] $BIN: FAIL (exit $RC)" | tee -a "$LOG"
        FAILURES=$((FAILURES + 1))
    fi
done

echo "" | tee -a "$LOG"
echo "results: $LOG" | tee -a "$LOG"
if [ "$FAILURES" -eq 0 ]; then
    echo "=== SUITE PASS (${#BENCHES[@]}/${#BENCHES[@]}) ===" | tee -a "$LOG"
else
    echo "=== SUITE FAIL ($FAILURES failure(s)) ===" | tee -a "$LOG"
    exit 1
fi
