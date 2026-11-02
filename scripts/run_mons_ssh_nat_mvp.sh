#!/bin/bash
set -euo pipefail
repository=$(cd "$(dirname "$0")/.." && pwd -P)
cd "$repository"
result=$(mktemp -d /private/tmp/mons-ssh-nat-mvp.XXXXXX)
printf '%s\n' "$result" > /private/tmp/mons-ssh-nat-mvp-current
printf 'SSH MVP output: %s\n' "$result"
sshd_pid= ssh_pid= proxy_pid= current=
cleanup() {
    local status=$?
    [[ -z $proxy_pid ]] || kill "$proxy_pid" 2>/dev/null || true
    [[ -z $ssh_pid ]] || kill "$ssh_pid" 2>/dev/null || true
    [[ -z $sshd_pid ]] || kill "$sshd_pid" 2>/dev/null || true
    [[ -z $sshd_pid ]] || wait "$sshd_pid" 2>/dev/null || true
    rm -f "$result/host-key" "$result/client-key"
    if [[ $status != 0 && -n $current ]]; then
        for log in "$current/client.log" "$current/transport.log" "$current/output" "$result/sshd.log"; do
            [[ ! -f $log ]] || tail -c 2500 "$log"
        done
    fi
}
trap cleanup EXIT

mkdir "$result/baseline"
git --no-lazy-fetch archive 7beeffa2728b77165be7f99ec3a33a79ec57ab89 | tar -xf - -C "$result/baseline"
zig build build-mons-nat-mvp -Dmvp-quicz-source="$result/baseline" --prefix "$result/baseline-bin" > "$result/build-baseline.log" 2>&1
zig build build-mons-nat-mvp --prefix "$result/probe-bin" > "$result/build-probe.log" 2>&1
ssh-keygen -q -t ed25519 -N '' -f "$result/host-key"
ssh-keygen -q -t ed25519 -N '' -f "$result/client-key"
port=$((40000 + RANDOM % 20000))
user=$(id -un)
cat > "$result/sshd_config" <<EOF
ListenAddress 127.0.0.1
Port $port
HostKey $result/host-key
PidFile $result/sshd.pid
AuthorizedKeysFile $result/client-key.pub
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
PermitRootLogin no
AllowUsers $user
PermitUserRC no
PrintMotd no
UseDNS no
LogLevel VERBOSE
StrictModes no
EOF
printf '[127.0.0.1]:%s %s\n' "$port" "$(cat "$result/host-key.pub")" > "$result/known_hosts"
/usr/sbin/sshd -t -f "$result/sshd_config"
/usr/sbin/sshd -D -e -f "$result/sshd_config" > "$result/sshd.log" 2>&1 &
sshd_pid=$!
for round in {1..50}; do
    if grep -q 'Server listening' "$result/sshd.log"; then break; fi
    kill -0 "$sshd_pid"
    sleep 0.1
done
grep -q 'Server listening' "$result/sshd.log"

cat > "$result/proxy.sh" <<'EOF'
#!/bin/bash
/usr/bin/perl -e 'open my $f, ">", shift @ARGV or die $!; print $f $$; close $f; alarm 12; exec @ARGV; die $!' "$1/proxy.pid" "$2" "$3" "$4" "$1/switch" 2> "$1/transport.log"
status=$?
printf '%s\n' "$status" > "$1/proxy.status"
exit "$status"
EOF
chmod 700 "$result/proxy.sh"

wait_for() {
    local pattern=$1 file=$2
    for round in {1..300}; do
        if grep -q "$pattern" "$file"; then return 0; fi
        if ! kill -0 "$ssh_pid" 2>/dev/null; then return 1; fi
        sleep 0.05
    done
    return 1
}

run_case() {
    local name=$1 binary=$2 mode=$3 expected=$4 nonce status before pushed after
    current="$result/$name"
    mkdir "$current"
    mkfifo "$current/input"
    exec 3<> "$current/input"
    nonce=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
    /usr/bin/perl -e 'alarm 15; exec @ARGV' /usr/bin/ssh -vv -tt -F /dev/null \
        -i "$result/client-key" -p "$port" -o IdentitiesOnly=yes -o BatchMode=yes \
        -o ConnectTimeout=5 -o ServerAliveInterval=0 -o StrictHostKeyChecking=yes \
        -o UserKnownHostsFile="$result/known_hosts" \
        -o "ProxyCommand='$result/proxy.sh' '$current' '$binary' '$mode' '$port'" \
        127.0.0.1 'env -i PATH=/usr/bin:/bin LC_ALL=C /bin/sh' \
        < "$current/input" > "$current/output" 2> "$current/client.log" 3>&- &
    ssh_pid=$!
    printf 'stty -echo\nPS1=""\nprintf "\\nMONS_SETUP_%%s\\n" "%s"\n' "$nonce" >&3
    wait_for "^MONS_SETUP_$nonce" "$current/output"
    proxy_pid=$(cat "$current/proxy.pid")
    printf 'printf "MONS_BEFORE_%s:%%s:%%s\\n" "$$" "$(tty)"\n' "$nonce" >&3
    wait_for "^MONS_BEFORE_$nonce:" "$current/output"
    touch "$current/switch"
    wait_for 'MVP SSH path_ready' "$current/transport.log"
    printf 'sleep 1\nprintf "MONS_PUSH_%s:%%s:%%s\\n" "$$" "$(tty)"\n' "$nonce" >&3
    if [[ $expected == success ]]; then
        wait_for "^MONS_PUSH_$nonce:" "$current/output"
        printf 'printf "MONS_AFTER_%s:%%s:%%s\\n" "$$" "$(tty)"\n' "$nonce" >&3
        wait_for "^MONS_AFTER_$nonce:" "$current/output"
        for phase in BEFORE PUSH AFTER; do
            [[ $(grep -c "^MONS_${phase}_$nonce:" "$current/output") == 1 ]]
        done
        before=$(tr -d '\r' < "$current/output" | grep "^MONS_BEFORE_$nonce:" | cut -d: -f2-)
        pushed=$(tr -d '\r' < "$current/output" | grep "^MONS_PUSH_$nonce:" | cut -d: -f2-)
        after=$(tr -d '\r' < "$current/output" | grep "^MONS_AFTER_$nonce:" | cut -d: -f2-)
        [[ -n $before && $before == "$pushed" && $before == "$after" && $before == *:/dev/* ]]
        touch "$current/switch.verify"
        wait_for 'MVP SSH transport_verified' "$current/transport.log"
        printf 'exit\n' >&3
    fi
    set +e
    wait "$ssh_pid"
    status=$?
    set -e
    ssh_pid=
    kill "$proxy_pid" 2>/dev/null || true
    proxy_pid=
    exec 3>&-
    printf '%s\n' "$status" > "$current/ssh.status"
    [[ $(grep -c 'Authenticated to .* using "publickey"' "$current/client.log") == 1 ]]
    [[ $(grep -c 'channel 0: new session' "$current/client.log") == 1 ]]
    [[ $(grep -c 'drive: accepted conn ' "$current/transport.log") == 1 ]]
    grep -q 'MVP SSH begin tls=verified' "$current/transport.log"
    if [[ $expected == success ]]; then
        [[ $status == 0 ]]
        grep -q 'old_during_push=0' "$current/transport.log"
        if [[ $mode == ssh_rebind ]]; then
            new_port=$(grep 'MVP SSH begin' "$current/transport.log" | sed 's/.*new_port=//')
            grep -q "MVP natural_commit .*remote_port=$new_port input_cid_matches_record=true" "$current/transport.log"
            commit_line=$(grep -n -m 1 'MVP natural_commit' "$current/transport.log" | cut -d: -f1)
            push_line=$(grep -n -m 1 'MVP SSH push_window_begin' "$current/transport.log" | cut -d: -f1)
            [[ $commit_line -lt $push_line ]]
        fi
        printf 'PASS %s: same authenticated SSH shell and PTY; Host push and later command complete\n' "$name"
    else
        [[ $status != 0 && $(cat "$current/proxy.status") == 142 ]]
        if grep -q "^MONS_PUSH_$nonce:" "$current/output"; then
            printf 'Unexpected SSH payload in timeout case: %s\n' "$name" >&2
            return 1
        fi
        if grep -q 'MVP SSH transport_verified' "$current/transport.log"; then
            printf 'Unexpected transport success in timeout case: %s\n' "$name" >&2
            return 1
        fi
        if [[ $mode == ssh_rebind ]]; then
            grep -q 'retired_destination_during_push' "$current/transport.log"
        else
            if grep -q 'MVP natural_commit' "$current/transport.log"; then
                printf 'Unexpected path commit in blocked-path case: %s\n' "$name" >&2
                return 1
            fi
        fi
        printf 'EXPECTED FAILURE %s: proxy deadline reached; SSH was not rebuilt\n' "$name"
    fi
}

run_case baseline-control "$result/baseline-bin/bin/mons-nat-mvp" ssh_control success
run_case baseline-rebind "$result/baseline-bin/bin/mons-nat-mvp" ssh_rebind timeout
run_case probe-control "$result/probe-bin/bin/mons-nat-mvp" ssh_control success
for round in 1 2 3; do
    run_case "probe-rebind-$round" "$result/probe-bin/bin/mons-nat-mvp" ssh_rebind success
done
run_case probe-blackhole "$result/probe-bin/bin/mons-nat-mvp" ssh_blackhole timeout
printf 'SSH MVP complete: five positive cases and two expected timeouts. iOS roaming remains unverified.\n'
