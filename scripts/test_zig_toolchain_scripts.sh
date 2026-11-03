#!/bin/sh
# Verify toolchain selection without Docker or benchmark execution.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
fixture=$(mktemp -d "${TMPDIR:-/tmp}/quicz-toolchain-test.XXXXXX")
trap 'rm -rf "$fixture"' EXIT HUP INT TERM
mkdir -p "$fixture/bin" "$fixture/scripts" "$fixture/toolchain" "$fixture/state"
cp "$root/scripts/run_bench_suite.sh" "$root/scripts/run_arm64_linux_check.sh" "$fixture/scripts/"

cat > "$fixture/bin/tool" <<'TOOL'
#!/bin/sh
set -eu
name=${0##*/}
printf '%s %s\n' "$name" "$*" >> "$TOOLCHAIN_TEST_STATE/commands"
case "$name:$1" in
    zig:version) echo 0.16.0 ;;
    zig17:version) echo 0.17.0 ;;
    zig17:build)
        printf '%s\n' "${ZIG_GLOBAL_CACHE_DIR:-}" > "$TOOLCHAIN_TEST_STATE/global-cache"
        exit 77
        ;;
    docker:inspect)
        [ "$2" = quicz-linux-arm64 ] && exit 0
        [ -f "$TOOLCHAIN_TEST_STATE/container" ] || exit 1
        [ "$2" = "$(cat "$TOOLCHAIN_TEST_STATE/container")" ]
        ;;
    docker:run)
        shift
        while [ "$#" -gt 0 ]; do
            if [ "$1" = --name ]; then
                printf '%s\n' "$2" > "$TOOLCHAIN_TEST_STATE/container"
                shift 2
                continue
            fi
            if [ "$1" = -v ]; then
                case "$2" in
                    *:/opt/zig-*) printf '%s\n' "${2#*:}" > "$TOOLCHAIN_TEST_STATE/mount" ;;
                esac
                shift 2
                continue
            fi
            shift
        done
        test -f "$TOOLCHAIN_TEST_STATE/mount"
        ;;
    docker:exec)
        if [ "$2" = quicz-linux-arm64 ]; then
            mount=/opt/zig-aarch64-linux-0.16.0
        else
            [ "$2" = "$(cat "$TOOLCHAIN_TEST_STATE/container")" ]
            mount=$(cat "$TOOLCHAIN_TEST_STATE/mount")
        fi
        case "$5" in
            *"$mount/zig "*) exit 0 ;;
            *) exit 127 ;;
        esac
        ;;
    *) exit 2 ;;
esac
TOOL
chmod +x "$fixture/bin/tool"
ln -s tool "$fixture/bin/zig"
ln -s tool "$fixture/bin/zig17"
ln -s tool "$fixture/bin/docker"
ln -s ../bin/tool "$fixture/toolchain/zig"
export TOOLCHAIN_TEST_STATE="$fixture/state"
export PATH="$fixture/bin:$PATH"

failures=0
# Stop the fixture compiler after build selection, before any benchmark runs.
benchmark_status=0
ZIG="$fixture/bin/zig17" bash "$fixture/scripts/run_bench_suite.sh" > "$fixture/benchmark.log" 2>&1 || benchmark_status=$?
if [ "$benchmark_status" -eq 1 ] &&
    grep -q '^# zig: 0.17.0$' "$fixture/benchmark.log" &&
    grep -q '^zig17 build ' "$fixture/state/commands"; then
    echo 'PASS: benchmark metadata uses the selected compiler'
else
    echo 'FAIL: benchmark metadata differs from the selected compiler' >&2
    failures=$((failures + 1))
fi

if [ "$(cat "$fixture/state/global-cache")" = "$(CDPATH= cd -- "$fixture" && pwd)/.zig-cache/global" ] &&
    grep -q '^zig17 build -Doptimize=fast$' "$fixture/state/commands"; then
    echo 'PASS: benchmark cache uses the Zig 0.17 environment variable'
else
    echo 'FAIL: benchmark cache uses an unsupported build argument' >&2
    failures=$((failures + 1))
fi

container_status=0
ZIG_AARCH64_LINUX_DIR="$fixture/toolchain" bash "$fixture/scripts/run_arm64_linux_check.sh" test > "$fixture/container.log" 2>&1 || container_status=$?
if [ "$container_status" -eq 0 ] &&
    [ "$(cat "$fixture/state/container")" = quicz-linux-arm64-zig-0.17.0 ]; then
    ZIG_AARCH64_LINUX_DIR="$fixture/toolchain" bash "$fixture/scripts/run_arm64_linux_check.sh" test >> "$fixture/container.log" 2>&1
    if [ "$(grep -c '^docker run ' "$fixture/state/commands")" -eq 1 ]; then
        echo 'PASS: versioned container preserves the legacy container and supports reuse'
    else
        echo 'FAIL: the versioned container was recreated' >&2
        failures=$((failures + 1))
    fi
else
    echo 'FAIL: the Linux check reused the legacy toolchain container' >&2
    failures=$((failures + 1))
fi

exit "$failures"
