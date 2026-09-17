#!/bin/sh
set -eu

output_path=${1:-zig-out/QuiczMobile.xcframework}
optimize=${QUICZ_OPTIMIZE:-ReleaseSafe}

if [ -e "$output_path" ]; then
    echo "output already exists: $output_path" >&2
    exit 2
fi

temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/quicz-mobile.XXXXXX")
trap 'rm -rf "$temporary_root"' EXIT HUP INT TERM

zig build mobile-static \
    -Dtarget=aarch64-ios \
    -Doptimize="$optimize" \
    --prefix "$temporary_root/device"
zig build mobile-static \
    -Dtarget=aarch64-ios-simulator \
    -Doptimize="$optimize" \
    --prefix "$temporary_root/simulator"

mkdir -p "$(dirname "$output_path")"
xcodebuild -create-xcframework \
    -library "$temporary_root/device/lib/libquicz_mobile.a" \
    -headers "$temporary_root/device/include" \
    -library "$temporary_root/simulator/lib/libquicz_mobile.a" \
    -headers "$temporary_root/simulator/include" \
    -output "$output_path"
