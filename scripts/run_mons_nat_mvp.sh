#!/bin/bash
set -euo pipefail
repository=$(cd "$(dirname "$0")/.." && pwd -P)
cd "$repository"
result=${MONS_NAT_MVP_OUTPUT:-$(mktemp -d /private/tmp/mons-nat-mvp.XXXXXX)}
case "$result" in /private/tmp/mons-nat-mvp.*) ;; *) echo 'Use a disposable /private/tmp/mons-nat-mvp.* output directory' >&2; exit 2 ;; esac
mkdir -p "$result"
printf 'MVP output: %s\n' "$result"
if [[ ! -d "$result/baseline" ]]; then
    mkdir "$result/baseline"
    git --no-lazy-fetch archive 7beeffa2728b77165be7f99ec3a33a79ec57ab89 | tar -xf - -C "$result/baseline"
fi
zig build build-mons-nat-mvp -Dmvp-quicz-source="$result/baseline" --prefix "$result/baseline-bin" >"$result/build-baseline.log" 2>&1
zig build build-mons-nat-mvp --prefix "$result/probe-bin" >"$result/build-probe.log" 2>&1

run_case() {
    local binary=$1 mode=$2 log=$3 expected=$4 status
    set +e
    /usr/bin/perl -e 'alarm 12; exec @ARGV' "$binary" "$mode" >"$log" 2>&1
    status=$?
    set -e
    if [[ $expected == success ]]; then
        [[ $status == 0 ]] || { tail -c 3000 "$log"; return 1; }
        grep -Fq "MVP PASS mode=$mode" "$log"
    else
        [[ $status == 142 ]] || { tail -c 3000 "$log"; return 1; }
        ! grep -Fq 'MVP PASS' "$log"
    fi
    grep -Fq 'MVP control_pass tls=verified' "$log"
    [[ $(grep -Fc 'drive: accepted conn ' "$log") == 1 ]]
    printf '%s mode=%s exit=%s\n' "$expected" "$mode" "$status"
}

run_case "$result/baseline-bin/bin/mons-nat-mvp" control "$result/baseline-control.log" success
run_case "$result/baseline-bin/bin/mons-nat-mvp" rebind "$result/baseline-rebind.log" timeout
grep -Fq 'retired_destination_during_push' "$result/baseline-rebind.log"
run_case "$result/probe-bin/bin/mons-nat-mvp" control "$result/probe-control.log" success
for round in 1 2 3 4 5; do
    log="$result/probe-rebind-$round.log"
    run_case "$result/probe-bin/bin/mons-nat-mvp" rebind "$log" success
    grep -Fq 'MVP natural_commit' "$log"
    grep -Fq 'input_cid_matches_record=true' "$log"
    grep -Fq 'old_during_push=0' "$log"
    commit_line=$(grep -n -m 1 'MVP natural_commit' "$log" | cut -d: -f1)
    push_line=$(grep -n -m 1 'MVP host_push_begin' "$log" | cut -d: -f1)
    [[ $commit_line -lt $push_line ]]
done
run_case "$result/probe-bin/bin/mons-nat-mvp" loss "$result/probe-loss.log" success
grep -Fq 'dropped_replacement=1' "$result/probe-loss.log"
grep -Fq 'old_during_push=0' "$result/probe-loss.log"
run_case "$result/probe-bin/bin/mons-nat-mvp" blackhole "$result/probe-blackhole.log" timeout
! grep -Fq 'MVP natural_commit' "$result/probe-blackhole.log"
printf 'MVP verdict: controlled first-path success; loss tolerance observed; production migration remains unverified.\n'
