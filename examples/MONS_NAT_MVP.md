# Mons NAT rebinding MVP

This is a disposable loopback experiment. It is not a production migration
implementation or an iOS roaming test.

The question is whether one existing Quicz client, connection and stream can
keep receiving Host-initiated data after a proxy changes its upstream UDP
source port. The proxy must discard replies addressed to the retired port.

Run the probe with `bash scripts/run_mons_nat_mvp.sh`.

The probe prints each phase and its observed path. A successful echo during
client activity is not sufficient. Passing requires a new payload initiated
by the Host after path validation. A blocked replacement path must fail.

Baseline and experimental binaries use separate source directories. The
baseline source is exported from the pinned local Git object. No downloads,
network configuration changes or product deployment are required.

## Results

The final run produced eight positive passes and two expected timeouts:

| Case | Result |
| --- | --- |
| Original runtime, unchanged port | Passed. Verified TLS and Host-initiated bytes arrived. |
| Original runtime, A-to-B port change | Failed as expected. Host push used retired A and was dropped. |
| Experimental runtime, unchanged port | Passed. |
| Experimental runtime, A-to-B port change | Five of five passed. Natural commit preceded the new Host push. |
| Experimental runtime, first replacement packet dropped | Passed with one observed drop. This establishes loss tolerance only. |
| Experimental runtime, replacement path blocked | Timed out as expected, without a natural commit or success report. |

All successful rebinding cases retained one client, accepted connection and
stream. The Host input CID matched the record source CID used by asynchronous
output. No packet addressed to the retired port was forwarded to the client.
The active Host-push phase observed zero packets addressed to that port.

The experiment changes only the server runtime's initial validation wiring
and installed-output path selection. It relies on the existing endpoint to
consume the actual response and commit the path. The observer runs inside
the drive owner. It does not write a route.

## Limits

The validation window is quiet. It has one IPv4 port-only change, no CID
rotation and no loss of the first validation challenge or response.
The candidate/token binding, validation retries, late responses, candidate
budgets and pending application-output isolation remain outside this probe.

The dropped packet is not correlated with encrypted STREAM metadata.
Do not call that case proof of integrated STREAM recovery. A blocked B is
a failure-detection case, not proof of rollback to a healthy A.

The port-only modes do not contain SSH, iOS, active socket replacement,
IPv6 or WSS. They cannot establish complete seamless terminal roaming.

Logs and the exported baseline are in `/private/tmp/mons-nat-mvp.BwUxxX/`.
This branch must not be merged as a feature.

## Real SSH gate

Run `bash scripts/run_mons_ssh_nat_mvp.sh` to test unmodified OpenSSH over
the same experimental QUIC stream. It connects to an isolated loopback
sshd with temporary keys and explicit Host-key verification. It requests
a real PTY. It does not change system SSH configuration or user keys.

The bridge forwards encrypted SSH bytes between OpenSSH's ProxyCommand
pipes, one QUIC stream, and one TCP connection to the temporary daemon.
The NAT change occurs after SSH authentication and a successful command.
A delayed remote command then emits a fresh random marker. Another command
must succeed afterward. Each marker contains the remote shell PID and PTY.
Terminal echo is disabled before these strictly matched markers.

The completed matrix has five positive passes and two expected failures:

| Case | Result |
| --- | --- |
| Original runtime, unchanged port | Passed with the same authenticated shell and PTY. |
| Original runtime, A-to-B port change | No PUSH marker arrived. The proxy reached its deadline and SSH exited with an error. |
| Experimental runtime, unchanged port | Passed. |
| Experimental runtime, A-to-B port change | Three of three passed, including Host output and a later command. |
| Experimental runtime, replacement path blocked | No natural commit or PUSH marker. The proxy reached its deadline. |

Each positive case has one public-key authentication, one SSH session
channel, one QUIC accept, and identical BEFORE/PUSH/AFTER shell PID and PTY.
All three rebindings naturally commit to the observed B port before the
Host-push window. The retired-path packet count is zero in that window.
No client, connection, stream, backend TCP connection, or SSH session is
recreated by the bridge.

The negative cases exit with proxy status 142 and SSH status 255. Their
logs establish failure after the port change. They do not independently
prove that the remote PUSH command executed or identify the discarded
packet as its stdout.

The matrix exits successfully. Separate process and listener checks confirm
that its recorded proxies and SSH children exited. The daemon listener
closed, and the runner removed its generated private keys.

Evidence is in `/private/tmp/mons-ssh-nat-mvp.ptARO6/`. This gate proves
real SSH composition in the controlled port-only case. It does not use
Mons NIOSSH, the mobile C ABI, iOS, active socket replacement, IPv6 or WSS.
It does not close the production migration limits listed above.

## Negative-gate regression

Run `bash scripts/test_mons_mvp_assertions.sh` to check the shell gates
without starting QUIC or SSH. It executes the actual extracted gate code
in separate Bash processes. Four clean timeout cases must pass. Six cases
with individual or combined forbidden success markers must fail.

The original gates incorrectly accepted all six contradictory cases.
All five standalone `! grep` checks now use explicit failure branches.
The same regression passes ten of ten checks. The real ten-case NAT and
seven-case SSH matrices also pass after this correction.

Corrected-run evidence is in `/private/tmp/mons-mvp-assertions.LJHUQ3/`,
`/private/tmp/mons-nat-mvp.3etMNv/` and
`/private/tmp/mons-ssh-nat-mvp.GDhHVh/`. Two independent reviews confirmed
that the finding is closed. That gate correction did not change the runtime.

## Physical iPhone prerequisite

The SSH gate and assertion correction are committed as `08dc32cd`.
The next gate uses an isolated NAT Probe App on the actual iPhone 14 Pro.
It validates the mobile C ABI through the controlled LAN proxy. It does
not change Wi-Fi or cellular service, and it does not replace Mons.

A native close preflight found an existing missing unlock when receive
returns `ConnectionClosed`. A normal reply released the lock. Remote close
returned the error while retaining the lock. A focused Zig test reproduced
the defect. The experiment now releases that lock before the same error
return. The same native preflight then passes both cases. Its source and
original failing evidence remain in `/private/tmp/mons-mobile-close-preflight.XOejvW/`.

The App links a separately built archive containing this fix. Its report
records the full local source identity. The original Mons archive and
dependency pin are unchanged. An existing wildcard development profile
signs the App without creating Apple credentials or online configuration.
The existing QuiczValidation App is preserved.

The first device attempt expired before any QUIC handshake. It is not a
passing run and does not establish the reason for the missing connection.
After local network authorization, a fresh bounded attempt passes on
iPhone 14 Pro / iOS 18.7.2:

- Native create, connect and open each occur once. Stream 0 remains valid.
- The bound client port stays unchanged. Every payload matches this run's token.
- The Host naturally commits to B before the new Host-push window.
- The Host receives the later input and final acknowledgment on that stream.
- The retired A packet count is zero during the Host-push window.
- Native close and destroy return before the App writes its passing result.

Both sides' results and the verified summary are in
`/private/tmp/mons-ios-nat-mvp.JTyW1O/retry-1/`. The independent App was
removed after collection. Both test Host processes exited. Mons and the
pre-existing QuiczValidation App retain their original installation metadata.

This is one controlled positive device run. It does not validate iPhone
interface roaming, IPv4 address changes, IPv6, WSS handover, NIOSSH, a real
terminal or failure cleanup on iOS. Actual Wi-Fi/cellular handover still
needs a stable public UDP test endpoint and a separate execution window.

After the native unlock and device entry were added, the ten assertion
checks, ten NAT cases and seven real SSH cases pass again. The existing
`zig build test-mobile-abi` target also exits successfully. Its unrelated-CA
tests deliberately log handshake rejection warnings. Formatting, shell
syntax and diff checks pass. Independent code/evidence review found no
blocking issue for this limited gate. These third-gate changes are not committed.

The device builder requires explicit, nonempty `MONS_QUICZ_FRAMEWORK` and
`MONS_QUICZ_EXPECTED_SOURCE` values. Use the isolated archive and the complete
source identity reported by its build. The builder has no vendor fallback.
It checks the full marker before packaging or signing.

Six source-input cases extend the shell regression to sixteen checks.
Before the correction, four missing/empty cases incorrectly passed.
Afterward, all sixteen checks pass. The complete builder rejects missing
inputs before creating its output. An explicit isolated-source invocation
still builds and signs successfully without installing another App.
