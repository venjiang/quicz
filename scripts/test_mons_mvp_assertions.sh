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
printf 'Assertion regression: checks=%s failures=%s\n' "$checks" "$failures"
[[ $failures == 0 ]]
