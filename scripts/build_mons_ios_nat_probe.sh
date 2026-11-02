#!/bin/bash
set -euo pipefail
repository=$(cd "$(dirname "$0")/.." && pwd -P)
offer=${1:?Expected an offer directory}
output=${2:?Expected an output directory}
profile=${3:?Expected an existing wildcard development profile}
framework=${MONS_QUICZ_FRAMEWORK:?Set MONS_QUICZ_FRAMEWORK to the isolated XCFramework}
expected_source=${MONS_QUICZ_EXPECTED_SOURCE:?Set MONS_QUICZ_EXPECTED_SOURCE to its complete source identity}
[[ $(cat "$framework/MonsSourceRevision.txt") == "$expected_source" ]]
app="$output/NATProbe.app"
mkdir -p "$app"
cp "$offer/offer.json" "$offer/server.der" "$app/"
cp "$framework/MonsSourceRevision.txt" "$app/client-source.txt"
cp "$profile" "$app/embedded.mobileprovision"
python3 - "$profile" "$output" <<'PY'
import hashlib, pathlib, plistlib, subprocess, sys
profile, output = sys.argv[1], pathlib.Path(sys.argv[2])
decoded = subprocess.run(['security', 'cms', '-D', '-i', profile], capture_output=True, check=True)
provision = plistlib.loads(decoded.stdout)
assert provision['Entitlements']['application-identifier'] == 'EJJLTDB36F.*'
assert provision['Entitlements']['get-task-allow'] is True
bundle = 'com.venjiang.mons.nat-probe'
entitlements = {'application-identifier': 'EJJLTDB36F.' + bundle,
    'com.apple.developer.team-identifier': 'EJJLTDB36F', 'get-task-allow': True,
    'keychain-access-groups': ['EJJLTDB36F.' + bundle]}
identities = subprocess.run(['security', 'find-identity', '-v', '-p', 'codesigning'], capture_output=True, text=True, check=True).stdout
identity = next(hashlib.sha1(cert).hexdigest().upper() for cert in provision['DeveloperCertificates']
    if hashlib.sha1(cert).hexdigest().upper() in identities)
(output/'signing-identity.txt').write_text(identity)
(output/'entitlements.plist').write_bytes(plistlib.dumps(entitlements))
info = {'CFBundleIdentifier': bundle, 'CFBundleExecutable': 'NATProbe', 'CFBundleName': 'NATProbe',
    'CFBundleDisplayName': 'NAT Probe', 'CFBundleVersion': '1', 'CFBundleShortVersionString': '0.1',
    'CFBundlePackageType': 'APPL', 'CFBundleSupportedPlatforms': ['iPhoneOS'], 'MinimumOSVersion': '17.0',
    'UIDeviceFamily': [1, 2], 'UILaunchScreen': {},
    'NSLocalNetworkUsageDescription': 'Run the isolated QUIC NAT rebinding test with this Mac.',
    'UIApplicationSceneManifest': {'UIApplicationSupportsMultipleScenes': False}}
(output/'NATProbe.app'/'Info.plist').write_bytes(plistlib.dumps(info))
PY
device="$framework/ios-arm64"
sdk=$(xcrun --sdk iphoneos --show-sdk-path)
SDKROOT="$sdk" xcrun swiftc -swift-version 5 -parse-as-library -target arm64-apple-ios17.0 -sdk "$sdk" \
    -import-objc-header "$device/Headers/quicz_mobile.h" \
    -L "$device" -lquicz_mobile -framework Security -framework Foundation -framework Network \
    -framework UIKit -framework SwiftUI "$repository/examples/mons_ios_nat_probe/NATProbe.swift" \
    -o "$app/NATProbe"
codesign --force --sign "$(cat "$output/signing-identity.txt")" --entitlements "$output/entitlements.plist" "$app"
codesign --verify --deep --strict "$app"
printf 'Built and signed isolated probe: %s\n' "$app"
