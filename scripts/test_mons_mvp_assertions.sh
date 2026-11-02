#!/bin/bash
set -euo pipefail
repository=$(cd "$(dirname "$0")/.." && pwd -P)
result=$(mktemp -d /private/tmp/mons-mvp-assertions.XXXXXX)
printf 'Assertion regression output: %s\n' "$result"

# Exercise the actual gate code without starting QUIC or SSH services.
awk '/^run_case\(\) \{/ {copy=1} copy {print} copy && /^}/ {exit}' \
    "$repository/scripts/run_mons_nat_mvp.sh" > "$result/nat-function.sh"
awk '/^run_case .* blackhole .* timeout$/ {copy=1; next} copy {print} copy && /^printf / && /MVP verdict:/ {exit}' \
    "$repository/scripts/run_mons_nat_mvp.sh" > "$result/nat-blackhole.sh"
awk '/^[[:space:]]*\[\[ \$status != 0 && / {copy=1} copy && /^    fi$/ {exit} copy {print}' \
    "$repository/scripts/run_mons_ssh_nat_mvp.sh" > "$result/ssh-negative.sh"
awk '/^app=/ {exit} {print}' "$repository/scripts/build_mons_ios_nat_probe.sh" > "$result/builder-prefix.sh"
mkdir -p "$result/layout/quicz/scripts" "$result/layout/mons/vendor/quicz/QuiczMobile.xcframework"
printf '%s\n' "$result/layout/quicz/scripts/build_mons_ios_nat_probe.sh" > "$result/builder-path.txt"
printf '%s\n' "$result/layout/mons/vendor/quicz/QuiczMobile.xcframework" > "$result/vendor-path.txt"
printf '7beeffa2728b77165be7f99ec3a33a79ec57ab89\n' > "$result/layout/mons/vendor/quicz/QuiczMobile.xcframework/MonsSourceRevision.txt"
mkdir "$result/framework"
printf 'local-git:review:sha256:isolated:optimize:ReleaseSafe\n' > "$result/framework/MonsSourceRevision.txt"

cat > "$result/fake-timeout.sh" <<'EOF'
#!/bin/bash
printf '%s\n' 'MVP control_pass tls=verified' 'drive: accepted conn 1' "$MVP_ASSERT_MARKER"
exit 142
EOF
chmod 700 "$result/fake-timeout.sh"
cat > "$result/nat-case.sh" <<'EOF'
set -euo pipefail
source "$MVP_ASSERT_ROOT/nat-function.sh"
run_case "$MVP_ASSERT_ROOT/fake-timeout.sh" rebind "$MVP_ASSERT_ROOT/nat.log" timeout
EOF
cat > "$result/nat-blackhole-case.sh" <<'EOF'
set -euo pipefail
result="$MVP_ASSERT_ROOT"
printf '%s\n' "$MVP_ASSERT_MARKER" > "$result/probe-blackhole.log"
source "$result/nat-blackhole.sh"
EOF
cat > "$result/ssh-case.sh" <<'EOF'
set -euo pipefail
current="$MVP_ASSERT_ROOT"
status=255
nonce=review
name=assertion-regression
mode="$MVP_ASSERT_MODE"
printf '142\n' > "$current/proxy.status"
printf '%s\n' "$MVP_ASSERT_MARKER" > "$current/output"
printf '%s\n' 'MVP retired_destination_during_push' "$MVP_ASSERT_MARKER" > "$current/transport.log"
ssh_negative() {
    source "$MVP_ASSERT_ROOT/ssh-negative.sh"
}
ssh_negative
EOF
cat > "$result/builder-case.sh" <<'EOF'
set -euo pipefail
unset MONS_QUICZ_FRAMEWORK MONS_QUICZ_EXPECTED_SOURCE
case "$MVP_ASSERT_MODE" in
    missing-both) ;;
    missing-framework)
        export MONS_QUICZ_EXPECTED_SOURCE=7beeffa2728b77165be7f99ec3a33a79ec57ab89 ;;
    missing-identity)
        export MONS_QUICZ_FRAMEWORK="$(cat "$MVP_ASSERT_ROOT/vendor-path.txt")" ;;
    empty-both)
        export MONS_QUICZ_FRAMEWORK='' MONS_QUICZ_EXPECTED_SOURCE='' ;;
    matching|mismatched)
        export MONS_QUICZ_FRAMEWORK="$MVP_ASSERT_ROOT/framework"
        export MONS_QUICZ_EXPECTED_SOURCE="$(cat "$MONS_QUICZ_FRAMEWORK/MonsSourceRevision.txt")"
        if [[ $MVP_ASSERT_MODE == mismatched ]]; then
            MONS_QUICZ_EXPECTED_SOURCE=unexpected
        fi ;;
    *) exit 2 ;;
esac
prefix=$(cat "$MVP_ASSERT_ROOT/builder-prefix.sh")
/bin/bash -c "$prefix" "$(cat "$MVP_ASSERT_ROOT/builder-path.txt")" unused-offer unused-output unused-profile
EOF

checks=0
failures=0
check() {
    local expected=$1 name=$2 entry=$3 marker=$4 mode=${5:-ssh_blackhole} status
    set +e
    MVP_ASSERT_ROOT="$result" MVP_ASSERT_MARKER="$marker" MVP_ASSERT_MODE="$mode" \
        /bin/bash -euo pipefail "$result/$entry" > "$result/$name.log" 2>&1
    status=$?
    set -e
    checks=$((checks + 1))
    if [[ $expected == accept && $status == 0 || $expected == reject && $status != 0 ]]; then
        printf 'PASS %s\n' "$name"
    else
        printf 'FAIL %s: expected=%s exit=%s\n' "$name" "$expected" "$status"
        failures=$((failures + 1))
    fi
}

check accept nat-timeout-clean nat-case.sh ''
check reject nat-timeout-pass nat-case.sh 'MVP PASS mode=rebind'
check accept nat-blackhole-clean nat-blackhole-case.sh ''
check reject nat-blackhole-commit nat-blackhole-case.sh 'MVP natural_commit connection=1'
check accept ssh-blackhole-clean ssh-case.sh ''
check reject ssh-push ssh-case.sh 'MONS_PUSH_review:123:/dev/ttys001'
check reject ssh-verified ssh-case.sh 'MVP SSH transport_verified'
check reject ssh-commit ssh-case.sh 'MVP natural_commit connection=1'
check reject ssh-combined ssh-case.sh $'MONS_PUSH_review:123:/dev/ttys001\nMVP SSH transport_verified\nMVP natural_commit connection=1'
check accept ssh-rebind-clean ssh-case.sh '' ssh_rebind
check reject builder-missing-both builder-case.sh '' missing-both
check reject builder-missing-framework builder-case.sh '' missing-framework
check reject builder-missing-identity builder-case.sh '' missing-identity
check reject builder-empty-both builder-case.sh '' empty-both
check reject builder-mismatched builder-case.sh '' mismatched
check accept builder-matching builder-case.sh '' matching
printf 'Assertion regression: checks=%s failures=%s\n' "$checks" "$failures"
[[ $failures == 0 ]]
