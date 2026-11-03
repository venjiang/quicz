# quicz Getting Started

This guide walks through building real client/server applications with quicz's
production I/O runtime (`std.Io` async + QUIC stream model). It covers the
HTTP/3 path (recommended for most applications), custom stream protocols, and
the advanced patterns (DATAGRAM, 0-RTT, server push, WebTransport).

quicz exposes four API layers — turnkey HTTP/3, runtime transport, TLS
endpoints, and a sans-IO core. This guide uses the top two; the lower layers
are documented in [API Layers](api-layers.md) with a comparison to
s2n-quic / quic-go / quinn / quiche / msquic / quic-zig.

Prerequisites: Zig 0.17.0. The library uses pure Zig and has no C library dependencies.

## 1. Add the dependency

```bash
zig fetch --save git+https://github.com/venjiang/quicz
```

In your `build.zig`:

```zig
const quicz_dep = b.dependency("quicz", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("quicz", quicz_dep.module("quicz"));
```

Then import it:

```zig
const quicz = @import("quicz");
```

## 2. Common setup: the event loop

Both server and client run on a Zig `std.Io` instance. The `Threaded` backend
executes async I/O on a thread pool; your application drives streams from
one or more async tasks.

```zig
var threaded = std.Io.Threaded.init(allocator, .{});
defer threaded.deinit();
const io = threaded.io();
```

## 3. HTTP/3 server

`runtime.Server` owns the socket, endpoint and connection lifecycle. Use
`serveH3` with a synchronous request handler.

```zig
const Server = quicz.runtime.server.Server;

// Handler: receives a fully decoded request, returns a Response.
fn handleRequest(req: quicz.h3_request.DecodedRequest) quicz.h3_request.Response {
    if (std.mem.eql(u8, req.path, "/")) {
        return .{ .status = 200, .body = "Hello from quicz HTTP/3!" };
    }
    // Streamed (chunked) response body — sent as multiple DATA frames.
    if (std.mem.eql(u8, req.path, "/stream")) {
        return .{
            .status = 200,
            .body_stream = quicz.h3_request.ResponseBody.fromRepeating(allocator, 'S', 65536) catch unreachable,
        };
    }
    return .{ .status = 404, .body = "not found" };
}

var server = try Server.init(allocator, io, .{
    .port = 4433,
    .alpn = &.{"h3"},
    .cert_der = &certificate_der,   // DER certificate
    .private_key = &server_private_key, // matching private key
});
defer server.deinit();
try server.serveH3(.{}, handleRequest); // options: qpack_max_table_capacity, qpack_blocked_streams

// Block until killed (serveLoop runs as a concurrent task).
server.drive_group.await(io) catch {};
```

Test with `curl --http3-prior https://127.0.0.1:4433/ -k -v` (a curl build with
HTTP/3 support).

### Response variants

| Field | Meaning |
|---|---|
| `.body = slice` | Single contiguous body, encoded as one DATA frame |
| `.body_stream = ResponseBody` | Chunked body (takes precedence over `body`) |
| neither | Bodyless response (HEADERS + fin) |

### Request body

The server aggregates request DATA frames up to `max_request_body_size`
(1 MiB by default). Inside the handler, `req.body` holds the full aggregated
body (or `null`). Oversized bodies are rejected with 413 + STOP_SENDING.

## 4. HTTP/3 client

```zig
const Client = quicz.runtime.client.Client;
const H3Client = quicz.runtime.h3_client.H3Client;

var client = try Client.init(allocator, io, .{
    .server_port = 4433,
    .server_name = "localhost",
    .alpn = &.{"h3"},
    .insecure_skip_verify = true, // null ca_bundle also skips verification
});
defer client.deinit();
try client.connect();

var h3cli = H3Client.init(allocator, &client, 4096, 8); // qpack cap, blocked streams
defer h3cli.deinit();
try h3cli.run(); // waits for the server SETTINGS

// Send a GET request.
const stream = try h3cli.sendRequest(.{
    .method = "GET",
    .path = "/",
    .authority = "localhost",
});
const resp = try h3cli.receiveResponse(stream);
if (resp.isSuccess()) {
    // resp.body is the aggregated response body (or null).
}
client.close();
```

### Streamed request body

For large uploads, `sendRequestStreamed` sends the body as bounded DATA
frames, blocking until fully drained (flow-control credit is awaited):

```zig
const body = try quicz.h3_request.ResponseBody.fromRepeating(allocator, 'A', 20 * 1024);
const stream = try h3cli.sendRequestStreamed(.{
    .method = "POST",
    .path = "/echo",
    .authority = "localhost",
}, body);
const resp = try h3cli.receiveResponse(stream);
```

## 5. Low-level stream echo (custom protocols)

For non-HTTP protocols, use `Server.serve` with a per-connection handler
(std.http model). Each connection gets its own handler task.

```zig
const ServerConnection = quicz.runtime.server.ServerConnection;

fn echoHandler(conn: ServerConnection) std.Io.Cancelable!void {
    var c = conn;
    var stream = c.acceptStream() catch return;
    var buf: [65536]u8 = undefined;
    while (true) {
        const n = stream.receive(&buf) catch return;
        if (n == 0) break; // EOF
        stream.send(buf[0..n], false) catch return;
    }
}

var server = try Server.init(allocator, io, .{
    .port = 4433,
    .alpn = &.{"hq-interop"},
    .cert_der = &certificate_der,
    .private_key = &server_private_key,
});
defer server.deinit();
try server.serve(&echoHandler);
```

On the client side, `connect()` then `send`/`receive` on a stream:

```zig
try client.connect();
const sid = try client.send("hello", false);
var buf: [4096]u8 = undefined;
const n = try client.receive(sid, &buf); // 0 = EOF
```

## 6. Certificates

The examples bundle a local test-only P-256 key pair (see any
`examples/*_loopback.zig`). For production:

- **macOS / arm64**: ECDSA P-256 certificates work.
- **Linux x86_64**: Zig 0.16's `std.crypto` has a known codegen bug for
  P-256/P-384/Ed25519 signature verification. Use **RSA certificates** and a
  **Release** build (`-Doptimize=fast`). An OpenSSL-generated RSA
  certificate verifies correctly on Linux.

`Server.Config` supports `bind_addr` (default `127.0.0.1`); set it to
`.{0,0,0,0}` to listen on all interfaces.

## 7. Common patterns

- **Per-connection handler task**: `Server.serve`/`serveH3` spawn one task per
  connection; each connection's resources are single-owner (no refcounting).
- **Non-blocking multistream**: for a handler that serves many streams, poll
  with `tryAcceptStreamId` / `tryReceiveStreamData` / `connStreamIds` and park
  on `waitStreamActivity` instead of blocking on one stream.
- **Concurrency**: `std.Io.Group.concurrent` runs independent client/server
  tasks; see `examples/multi_client_bench.zig` for N concurrent clients.

## 8. Advanced patterns

### Server → client unidirectional push

A server can open a unidirectional stream and push data the client reads
(`openUniStream` on the connection, `openUniStream`/`sendOnStream` on the
client). The client must enable server-uni-stream polling (`enableH3()`) for
the drive task to deliver them.

```zig
// server handler
var push = try conn.openUniStream();          // server-initiated uni stream
try push.send("server push payload", true);   // fin

// client
try client.enableH3();                        // poll server uni streams
// ... after connect; the pushed stream is a client-opened id the client reads
```

### Multi-client concurrency

`std.Io.Group.concurrent` runs N independent clients against one server; each
client is its own `runtime.Client` with its own drive task, so they parallel
across cores. See `examples/multi_client_bench.zig` (concurrent handshakes +
aggregate throughput) and `examples/stability_bench.zig` (long-run leak check).

### DATAGRAM, 0-RTT, WebTransport, lower-layer driving

These live on the lower API layers (see [API Layers](api-layers.md)) rather
than the runtime's stream API:

- **DATAGRAM (RFC 9221)**: unreliable application messages on the sans-IO core
  (`Connection` datagram methods + `h3_datagram`). Runnable:
  `examples/datagram_echo.zig` (`DATAGRAM Throughput`).
- **0-RTT**: session-resumption early data via `Tls13ClientEndpoint` +
  `session_cache`; without the runtime's socket loop. Runnable:
  `examples/zero_rtt_echo.zig`, `examples/udp_zero_rtt_loopback.zig`.
- **WebTransport**: `src/h3/webtransport.zig` builds a WebTransport session on
  `h3_connection` (extended CONNECT).
- **Sans-IO driving**: `Connection` + `endpoint_types` +
  `EndpointConnectionLifecycle` — feed datagrams, poll output, no TLS/socket.
  See `examples/interop_event_loopback.zig` and the `examples/udp_*_loopback.zig`
  set; `examples/udp_path_validation_loopback.zig` (connection migration + path
  validation) and `examples/udp_key_update_loopback.zig` (key update) are the
  richest examples.

## See also

- `docs/en/api-layers.md` — high/low layer map + comparison to other stacks.
- `docs/en/api-reference.md` — full signature reference.
- `docs/en/architecture.md` — internal design.
- `examples/h3_runtime_loopback.zig`, `examples/io_echo.zig`,
  `examples/multi_client_bench.zig` — runnable examples.
