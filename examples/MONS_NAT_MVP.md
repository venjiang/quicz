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

This probe does not contain SSH, iOS, active socket replacement, IPv6 or WSS.
It therefore cannot establish complete seamless terminal roaming.

Logs and the exported baseline are in `/private/tmp/mons-nat-mvp.BwUxxX/`.
This branch must not be merged as a feature.
