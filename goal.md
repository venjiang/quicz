# quicz Goal Snapshot

Last updated: 2026-07-02

This file is the compact recovery context for continuing the current `quicz`
transport work. The authoritative task matrix remains in
`docs/en/quic_transport_tasks.md` and `docs/zh-CN/quic_transport_tasks.md`.

## Current Goal

Implement and verify the IETF QUIC transport protocol plan for `quicz` in Zig.
The active work is paused after the latest committed feature:

- `4126899 feat: add installed-key drain option steps`
- remote state at the last check: `main` matched `origin/main`

The main task has not changed: keep moving the QUIC transport core toward a
usable QUIC v1 client/server stream transport with TLS integration, endpoint
lifecycle ownership, packet protection, recovery, close/cleanup, and interop
evidence.

## Scope Boundary

The first usable target is a practical QUIC v1 transport subset:

- UDP endpoint lifecycle for accept/connect, route lookup, send/receive,
  timers, close, and cleanup.
- TLS 1.3 integration through a narrow `TlsBackend` boundary.
- TLS-owned Initial, Handshake, optional 0-RTT, and 1-RTT secret installation.
- Protected STREAM I/O, ACK cleanup, PTO/loss timer service, key discard, and
  close through one lifecycle owner.
- Minimal external interop evidence after the local TLS-owned loop works.

Out of the first milestone unless needed by interop:

- HTTP/3 and QPACK.
- RFC 9221 DATAGRAM.
- Full QUIC v2 and full RFC 9368 compatible version negotiation.
- Multipath, qlog, PMTU discovery, GSO/GRO, and advanced congestion controller
  selection.

## Implementation Rules

- This is a Zig 0.16 project. New C interop must use `build.zig`
  `b.addTranslateC` plus Zig-side `@import("c")`.
- Do not add new `@cImport` usage or hand-written C `extern` bindings for new
  C-library integration.
- Use maintained libraries for mature non-core capabilities. TLS is not the
  core value of this repository, so keep using a C TLS library for now.
- `quicz` owns QUIC transport state, packet processing, recovery, endpoint
  lifecycle, and the public Zig API.
- Do not use codegraph for this repository; search with `rg`, direct file
  reads, and build/test output.
- Public README and docs must explain what the project is, what is implemented,
  what is missing, how to run examples, and how developers can extend/debug it.
- Public docs should avoid internal phrasing and external implementation names.
- Core code changes come before examples; examples validate core behavior.
- After each completed feature, commit and push to `origin/main`.
- When adding or changing functionality, split `src/lib.zig` naturally along
  real ownership boundaries. Do not do an unrelated large split. If a type is
  tightly coupled to `Connection`, split `Connection` first or keep the type in
  place.

## Validation Standard

For a core feature, default verification should include:

- `zig fmt --check src/lib.zig src/quic/endpoint_types.zig`
- `zig ast-check src/lib.zig`
- focused tests for the new path
- public wording scan using the forbidden-term regex from the current working
  convention
- `git diff --check`
- `zig build test --summary all`
- `zig build --summary all`

For docs-only recovery-context updates, at minimum run:

- `git diff --check`
- the forbidden wording scan, expanded to include `goal.md`

## Completed Recently

- Added single-connection pending-work installed-key output steps:
  `processPendingWorkAndPollDatagramWithInstalledKeyOptions()` and
  `processPendingWorkAndDrainDatagramsWithInstalledKeyOptions()`.
- Moved installed-key output option to recovery-space semantics into
  `EndpointPollInstalledKeyDatagramOptions.recoveryPacketNumberSpace()` in
  `src/quic/endpoint_types.zig`.
- Added installed-key 1-RTT receive-to-drain explicit-options entry points:
  `processProtectedShortDatagramWithInstalledKeysAndDrainDatagramsWithInstalledKeyOptions()`,
  `processProtectedShortDatagramWithInstalledKeysOrCloseAndDrainDatagramsWithInstalledKeyOptions()`,
  `processRoutedProtectedShortDatagramWithInstalledKeysAndDrainDatagramsWithInstalledKeyOptions()`,
  and
  `processRoutedProtectedShortDatagramWithInstalledKeysOrCloseAndDrainDatagramsWithInstalledKeyOptions()`.
- Kept older Application-only drain entry points as compatibility wrappers that
  delegate to the explicit-options APIs.
- Updated the English and Chinese transport task docs for the explicit
  installed-key output option work.

## Current Evidence

- `build.zig` pins the project to Zig `0.16.0`.
- Existing C TLS examples are already on `b.addTranslateC` plus `@import("c")`.
- Current TLS evidence includes `TlsBackend`, C-object adapter coverage,
  OpenSSL probe, OpenSSL pair transcript, and OpenSSL-backed adapter examples.
- Recent full verification before this snapshot passed:
  `zig build test --summary all` with `996/996`, and
  `zig build --summary all` with `115/115`.
- The latest checked worktree state before this file was added was clean:
  `## main...origin/main`.

## Pending Work

Highest priority:

- Build the endpoint-owned live TLS handshake/socket loop.
- Move from installed-key/mock-key happy paths to TLS-owned secret installation
  on the normal path.
- Prove local UDP client/server stream echo through one lifecycle owner:
  accept/connect, handshake confirmation, STREAM delivery, ACK cleanup,
  loss/PTO timer service, key discard, protected close, and route cleanup.

Next priorities:

- Keep shaping an embeddable socket API where callers can own UDP sockets,
  connection maps, timers, and datagram queues.
- Add a minimal interop command or example after the local TLS-owned loop is
  real.
- Add TLS/interop observability that reports useful counters and failure
  reasons without printing key material.
- Continue small, natural source-file splits when touching functionality.

## Do Not Repeat

- Do not spend time trying codegraph on this repository.
- Do not write a parallel QUIC implementation path when existing helpers cover
  the behavior.
- Do not treat backend-drive drain APIs as missing without checking signatures;
  current backend drain families already accept
  `EndpointPollInstalledKeyDatagramOptions`.
- Do not mark RFC rows `Done` while TLS-owned live socket loop or interop proof
  is missing.
- Do not expand public docs with internal wording or external implementation
  names.
- Do not make examples the main deliverable unless the core path they validate
  was implemented or changed.

## Next Commands

Start with current state:

```bash
git status --short --branch
git log --oneline --decorate -5
rg -n "EndpointPollInstalledKeyDatagramOptions|WithInstalledKeyOptions|processPendingWorkAnd|processProtectedShortDatagramWithInstalledKeys" src/lib.zig src/quic/endpoint_types.zig docs/en/quic_transport_tasks.md docs/zh-CN/quic_transport_tasks.md README.md README_zh-CN.md
```

If continuing core implementation, first find a real gap:

```bash
rg -n "processProtected.*Drain|processRoutedProtected.*Drain|DriveCryptoBackend.*Drain|PollDatagramWithInstalledKeyOptions|DrainDatagramsWithInstalledKeyOptions" src/lib.zig
rg -n "test \".*(installed-key|Handshake|1-RTT|PTO|drain|backend|lifecycle)" src/lib.zig
```

Before committing a feature:

```bash
zig fmt --check src/lib.zig src/quic/endpoint_types.zig
zig ast-check src/lib.zig
zig build test --summary all
zig build --summary all
git diff --check
rg -n "$FORBIDDEN_PUBLIC_WORDS" README.md README_zh-CN.md docs src goal.md
git status --short --branch
```

Then commit and push:

```bash
git add <changed-files>
git commit -m "<human feature summary>"
git push origin HEAD:main
```
