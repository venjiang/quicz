#!/usr/bin/env bash
# Native aarch64 Linux verification for quicz.
#
# The old `quicz-linux` container is an x86_64 image emulated on Apple Silicon
# (Virtualization.framework, CPU "VirtualApple") and is NOT a faithful Linux
# x86_64 environment: it reproduces spurious `error.InvalidPacket` on the
# loopback data path. Real Linux x86_64 is covered by GitHub Actions CI.
#
# This script drives a native aarch64 Linux container (QEMU-free on Apple
# Silicon) with the local repo mounted read-write, so Linux checks run at
# native speed and match the arm64 macOS + CI results.
#
# Prereqs:
#   - zig-linux-aarch64-0.17.0.tar.xz extracted somewhere (e.g. /tmp)
#   - docker with --platform linux/arm64 support
#
# Usage: scripts/run_arm64_linux_check.sh [cmd]
#   cmd: e2e     - run run-h3-runtime-loopback (fast)
#        test    - full zig build test (aarch64 Linux has no std codegen bugs)
#        all     - both (default)

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
ZIG_DIR="${ZIG_AARCH64_LINUX_DIR:-/tmp/zig-aarch64-linux-0.17.0}"
CONTAINER="quicz-linux-arm64-zig-0.17.0"
ZIG="/opt/zig-aarch64-linux-0.17.0/zig"

if [ ! -x "$ZIG_DIR/zig" ]; then
    echo "error: Zig aarch64-linux not found at $ZIG_DIR (set ZIG_AARCH64_LINUX_DIR)" >&2
    exit 1
fi

if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
    echo "creating $CONTAINER (native aarch64)..."
    docker run -d --platform linux/arm64 --name "$CONTAINER" \
        -v "$REPO:/src/quicz" \
        -v "$ZIG_DIR:/opt/zig-aarch64-linux-0.17.0" \
        --entrypoint sleep ubuntu:24.04 infinity >/dev/null
fi

run_cmd() {
    docker exec "$CONTAINER" bash -c "cd /src/quicz && $ZIG $*"
}

case "${1:-all}" in
    e2e)
        run_cmd build run-h3-runtime-loopback -Doptimize=fast
        ;;
    test)
        run_cmd build test --summary all
        ;;
    all)
        run_cmd build run-h3-runtime-loopback -Doptimize=fast
        run_cmd build test --summary all
        ;;
    *)
        echo "usage: $0 [e2e|test|all]" >&2
        exit 2
        ;;
esac
