# quicz CLI

`quicz` is a standalone QUIC / HTTP/3 development tool for daily work. It
references the quicz library as a normal package dependency; the library itself
does not bundle this CLI.

[简体中文](README_zh-CN.md)

## Build

```bash
cd cli
zig build                  # produces cli/zig-out/bin/quicz
zig build run -- --help
zig build test             # CLI unit tests
```

## Install

From the repository root, build a Release binary and install it into your
PATH:

```bash
make install-local                  # recommended: installs to $HOME/.local/bin
make install PREFIX="$HOME/.local"  # same, with an explicit prefix
make install                        # installs to /usr/local/bin/quicz (may need sudo)
```

`make install-local` (or `make install PREFIX="$HOME/.local"`) builds with
`-Doptimize=ReleaseFast` and installs the standalone binary to
`$HOME/.local/bin/quicz`. On macOS `/usr/local/bin` is usually not writable by
the current user, so prefer this target and add `$HOME/.local/bin` to your
`PATH` (e.g. `export PATH="$HOME/.local/bin:$PATH"` in your shell profile).
Remove the CLI with `make uninstall PREFIX="$HOME/.local"`.

## Subcommands

```bash
# H3 request client: GET/POST, prints status, response body and connection metrics
quicz h3 https://127.0.0.1:4433/hello.txt -k
quicz h3 https://host:4433/api -k -X POST -H 'content-type: application/json' --data '{"ok":true}' --timeout-ms 15000
quicz h3 https://host/api -d 'a=1&b=2'             # -d implies POST + form content-type
quicz h3 https://host/api -A 'my-agent/1.0'        # custom user-agent (default: quicz/0.1.0)
quicz h3 https://host/api -u 'user:pass'           # HTTP Basic auth
quicz h3 https://host/api -e 'https://ref.example/' # Referer header
quicz h3 https://host/api -b 'sid=abc123'          # Cookie header
quicz h3 https://host/api -T ./file.bin            # PUT upload (octet-stream)
quicz h3 https://host/api -G -d 'a=1&b=2'          # GET with data as URL query
quicz h3 https://host/api --max-filesize 100000    # fail if response body is larger
quicz h3 https://host/api --resolve host:443:127.0.0.1   # force host to an IPv4 address
quicz h3 https://host/api -v                      # verbose: DNS/connect/redirect tracing
quicz h3 https://host/api --max-time 30            # whole-request timeout in seconds
quicz h3 https://host/api --connect-timeout 5      # handshake timeout in seconds
quicz h3 https://host/api -o /dev/null -w 'code=%{http_code} time=%{time_total_ms}ms\n'
quicz h3 https://host/api -i -L -s -f -o resp.html # headers, redirects, silent, fail on 4xx/5xx, save body
quicz h3 https://host/api -I                          # HEAD request, headers only
quicz h3 https://host/api -X POST --data @body.json   # upload a request body from a file
quicz h3 https://host/api -D headers.txt              # dump response headers to a file
quicz h3 https://host/api -o -                        # write body to stdout explicitly

# HTTP/3/QUIC health probe: pass/fail verdict + failure stage (see below)
quicz probe https://example.com --json
quicz probe https://example.com -k --connect-timeout 5 --max-time 10
quicz probe https://127.0.0.1:4433/ -k --resolve example.com:443:127.0.0.1

# Static file server: HTTPS over TCP (browser) + HTTP/3 + /metrics + /echo
quicz serve --dir ./dist --port 4433
quicz serve --dir ./dist --port 4433 --cert cert.pem --key key.pem
quicz serve --dir ./dist --index index.htm         # custom index file (default index.html)
curl -k https://127.0.0.1:4433/                    # browsers open this URL (self-signed: trust it)
quicz h3 https://127.0.0.1:4433/echo -k -d 'ping'    # HTTP/3 client: /echo reflects method/path/authority/body

# Raw QUIC stream echo: verify quicz interop with external peers
quicz echo --server --port 4433
quicz echo --client 127.0.0.1 4433 --data "ping"

# Benchmark: handshake latency + single-stream throughput
# (peer is `quicz echo --server`)
quicz bench 127.0.0.1 4433 --size 1048576
```

## Probe (HTTP/3 service health check)

`quicz probe <url>` runs a single-shot HTTP/3/QUIC health check and attributes
failure to one stage: DNS resolution, UDP reachability, QUIC/TLS handshake or
the HTTP/3 request. It is the local diagnostic entry point of the `quicz.md`
product plan (QUIC-aware probe/exporter).

A scheme-less URL (`example.com`, `host:8443/`) is treated as `https://`
(curl-like convenience). An explicit non-https scheme (`http://`, `ftp://`,
...) is rejected with a usage error and exit code 2 instead of being silently
rewritten. Exit codes: 0 = all checks passed, 1 = probe failure (see
`failure_stage`), 2 = usage error.

Checks, in order:

1. URL parsing (https only)
2. DNS resolution (resolved IPv4 is reported)
3. QUIC 1-RTT handshake with TLS 1.3 and ALPN `h3` (certificate verified
   against the system CA bundle unless `-k` / `--ca` is given)
4. One HTTP/3 GET on the URL path

Output is a text report by default; `--json` emits a structured result for
CI, and `--prometheus` emits Prometheus text exposition format (metric names
follow the `quicz.md` plan: `quic_probe_success`, `quic_handshake_success`,
`quic_alpn_h3_success`, `quic_http3_request_success`, `quic_failure_stage`,
`quic_handshake_duration_seconds`, `quic_request_duration_seconds`) so a
scrape endpoint can wrap a probe directly. Exit code is 0 when every check
passes, 1 otherwise.

Failure stages: `invalid_url`, `dns_resolve_failed`, `udp_timeout`,
`quic_handshake_failed`, `tls_cert_failed`, `http3_request_failed`. The
distinction between `udp_timeout` (nothing ever arrived on UDP: blackholed,
firewalled, or a closed port) and `quic_handshake_failed` (UDP works, but the
handshake failed) is based on whether any UDP datagram was received, which the
runtime client now tracks (`Client.datagramsReceived`).

```bash
./zig-out/bin/quicz probe https://cloudflare-quic.com/ --json
./zig-out/bin/quicz probe https://127.0.0.1:4433/ -k          # local pass
./zig-out/bin/quicz probe https://127.0.0.1:4544 -k            # closed port -> udp_timeout
./zig-out/bin/quicz probe https://example.com --prometheus     # scrape endpoint format
```

Known limits: the client only negotiates `h3`, so `alpn_not_h3` and
HTTP/2 fallback detection are not yet surfaced; these are a follow-up stage.

## Real-world H3 verification

The `h3` subcommand is verified end to end against real online HTTP/3
servers (QUIC handshake + HTTP/3 + QPACK), then exercises a local `serve`
round trip:

```bash
../scripts/cli_h3_live_test.sh                  # live servers + local round trip
../scripts/cli_h3_live_test.sh --skip-live      # local round trip only
```

Live targets are `https://cloudflare-quic.com/` and `https://www.fastly.com/`;
each must return `HTTP/3 200` with a non-empty body. Direct commands produce
the same result:

```bash
./zig-out/bin/quicz h3 https://cloudflare-quic.com/ --timeout-ms 25000
# HTTP/3 200
# <full response body>
```

Cloudflare's edge inserts GREASE frames before the first HEADERS frame on
request/response streams (RFC 9114 §7.2.8). The runtime parser skips reserved
and unknown frame types while scanning for HEADERS (RFC 9114 §9). Regression
tests cover both directions:

- `src/h3/client.zig` - "H3Client skips GREASE frames before response HEADERS"
- `src/h3/server.zig` - "H3Server skips GREASE frames before request HEADERS"

## Certificate verification

`h3` verifies the server certificate against the system CA bundle by default.
Use `-k` to skip verification, or `--ca /abs/path.pem` to trust a custom CA:

```bash
./zig-out/bin/quicz h3 https://cloudflare-quic.com/          # verify against system CAs
./zig-out/bin/quicz h3 https://host/api -k                   # skip verification
./zig-out/bin/quicz h3 https://host/api --ca /abs/ca.pem     # trust a specific CA
```

The system bundle is loaded from `/etc/ssl/cert.pem` (macOS, Debian/Ubuntu),
`/etc/ssl/certs/ca-certificates.crt`, or `/etc/pki/tls/certs/ca-bundle.crt`.
If no system bundle is found, verification is disabled and a warning is
printed.

## Request options

- `-d` / `--data` sends a request body and implies `POST` plus
  `content-type: application/x-www-form-urlencoded`; `--data @file` reads the
  body from a file.
- `-A` / `--user-agent` overrides the default `User-Agent: quicz/0.1.0`;
  any `-H user-agent:` header is replaced.
- `-u` / `--user user:pass` adds HTTP Basic auth; `-e` / `--referer` sets the
  `Referer` header; `-b` / `--cookie 'name=value'` sets the `Cookie` header.
- `-b @file` reads request cookies from a Netscape cookie jar
  (curl-compatible format); `-c` / `--cookie-jar FILE` persists `Set-Cookie`
  response headers into a Netscape jar. With `-L`, cookies collected on each
  redirect hop are sent on the following hop automatically.
- `-T` / `--upload-file FILE` sends a PUT with the file as the body and
  `content-type: application/octet-stream` unless overridden.
- `-T` / `--upload-file FILE` sends a PUT with the file as the body and
  `content-type: application/octet-stream` unless overridden.
- `-G` / `--get` turns `--data` into a URL query string and keeps the method
  GET; `--max-filesize BYTES` fails the request when the response body is larger.
- `-w` / `--write-out FORMAT` prints curl-style variables to stdout, e.g.
  `%{http_code}` `%{url_effective}` `%{time_total_ms}` `%{time_connect_ms}`
  `%{size_download}` `%{num_redirects}`; `\n`/`\r`/`\t` escapes are honored.
- `--resolve host:port:addr` overrides DNS for that host/port (IPv4 only),
  which is handy for testing a real hostname against a local server.
- `--connect-timeout` / `--connect-timeout-ms` bounds only the QUIC handshake;
  `--max-time` / `--timeout-ms` caps the whole request (default 10s).
- `-v` / `--verbose` traces DNS resolution, connects, redirects, and request
  lines to stderr.
- `-o -` writes the response body to stdout; other `-o` paths write to a file.

`serve` lists subdirectories when they have no index file, and `--index FILE`
chooses the index file name served for directory paths.

## Limits

- The H3 client and server currently support IPv4 literals and `localhost`; `--ca` requires an absolute PEM path.
- `serve` listens on TCP (HTTPS over TLS, browser-friendly) and UDP (HTTP/3).
  Browsers open `https://127.0.0.1:PORT/` (self-signed cert: click through or
  trust it); HTTP responses include `Alt-Svc: h3=":PORT"; ma=86400` so the
  browser upgrades to HTTP/3 once it trusts the origin. `quicz h3
  https://127.0.0.1:PORT/ -k` (or `--ca`) exercises the HTTP/3 endpoint.
- `bench` connects to `echo --server` in insecure mode; it measures the transport path, not certificate verification.
- Client subcommands default to a 10s timeout (`--timeout-ms`) so a missing or stalled server fails instead of hanging.
