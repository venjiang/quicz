# quicz API Reference

Reference for the production `runtime` API and the `h3_request` types. All
paths are relative to the `quicz` import root. Unless noted, methods are
blocking-in-async (they suspend the calling async frame until the operation
completes or the connection closes).

## Top-level namespace (`src/lib.zig`)

The top level exports ~94 names. They fall into three layers; most
applications only touch the first.

**1. Production entry points** — build HTTP/3 or QUIC apps:

```zig
quicz.runtime                      // { server, client, h3_server, h3_client }
quicz.h3_request                   // Request / Response / ResponseBody / decoded types
quicz.h3_server / quicz.h3_client  // transport-agnostic H3 state machines
quicz.h3 / quicz.qpack / quicz.h3_connection / quicz.h3_limits / quicz.h3_datagram
quicz.webtransport                 // WebTransport session
quicz.Connection / quicz.Config    // transport-level connection + config
quicz.Tls13ClientEndpoint / quicz.Tls13ServerEndpoint   // handshake endpoints
quicz.Tls13ClientTransport / quicz.Tls13ServerTransport // per-conn transports
quicz.CryptoBackend / quicz.tls13  // TLS backend surface
```

**2. Low-level driver / extension modules** — for custom event loops or
protocol extensions; reachable when the runtime is not a fit:

```zig
quicz.endpoint_types               // Endpoint* driver result/error types
quicz.endpoint / quicz.EndpointConnectionLifecycle / quicz.EndpointConnectionRegistry
quicz.protection / quicz.packet / quicz.frame / quicz.recovery   // RFC 9000/9001
quicz.transport_parameters / quicz.transport_error / quicz.address_validation_token
quicz.pacer / quicz.cubic / quicz.pmtu / quicz.gso / quicz.migration / quicz.multipath
quicz.metrics / quicz.session_cache / quicz.connection_pool / quicz.udp_event_loop
quicz.zero_rtt / quicz.lifecycle_options / quicz.buffer / quicz.qlog
```

**3. Primitives / tools** — used by the layers above and by interop testing:

```zig
quicz.tls_pem / quicz.pq_kex / quicz.tls13_backend   // TLS material + backend plumbing
quicz.duration / quicz.qlog                          // time + qlog emission
quicz.fuzz_targets / quicz.stress_test               // harness material
```

## `runtime.server.Server`

### `Config`

| Field | Type | Default | Notes |
|---|---|---|---|
| `port` | `u16` | — | UDP listen port (loopback by default) |
| `alpn` | `[]const []const u8` | — | ALPN list, e.g. `&.{"h3"}` |
| `cert_der` | `[]const u8` | — | DER certificate |
| `private_key` | `[]const u8` | — | Private key (`.ecdsa_p256_sha256`; RSA on Linux) |
| `prefer_chacha20` | `bool` | `false` | Prefer ChaCha20-Poly1305 |
| `bind_addr` | `?[4]u8` | `null` | IPv4 to bind; null = `127.0.0.1`, `.{0,0,0,0}` = all |

Fixed transport params: `initial_max_data`/`stream_data` = 10 MiB,
bidi/uni streams = 128, `max_datagram_size` = 8192, idle timeout = 30 s.

### Lifecycle

```zig
pub fn init(allocator, io: std.Io, config: Config) !Server
pub fn start(self: *Server) !void              // idempotent; spawns recv+drive tasks
pub fn stop(self: *Server) void                // sets stopping, wakes loops
pub fn serve(self: *Server, handler: HandlerFn) !void   // start + spawn per-conn handlers
pub const H3ServeOptions = struct { qpack_max_table_capacity: u64 = 4096, qpack_blocked_streams: u64 = 8 };
pub fn serveH3(self: *Server, options: H3ServeOptions, handler: h3_server.RequestHandler) !void
pub fn deinit(self: *Server) void              // stop + cancel/await drive_group, free resources
pub const HandlerFn = *const fn (ServerConnection) std.Io.Cancelable!void
pub const Metrics = struct { active_connections, stream_bytes_sent/received, total_bytes_in_flight, smoothed_rtt_us, rttvar_us, congestion_window, packets_lost, packets_retransmitted }
pub fn metricsSnapshot(self: *Server) Metrics    // aggregate stats across live connections (monitoring)
pub drive_group: std.Io.Group                   // field; await it to block until shutdown
```

### Connection / stream methods (address by `conn_id: u64`)

| Method | Signature | Semantics |
|---|---|---|
| `accept` | `(self) !ServerConnection` | Block until next new connection |
| `acceptStreamId` | `(self, conn_id) !u64` | Block until stream has data; `error.ConnectionClosed` when conn closes |
| `receiveStreamData` | `(self, conn_id, sid, buf) !usize` | Blocking read; `0` = EOF |
| `tryAcceptStreamId` | `(self, conn_id) !?u64` | Non-blocking; `null` if none |
| `tryReceiveStreamData` | `(self, conn_id, sid, buf) !?usize` | Non-blocking; `null`=no data, `0`=EOF, `n`=bytes |
| `connStreamIds` | `(self, conn_id, out: []u64) usize` | Snapshot currently-receiving stream ids |
| `waitStreamActivity` | `(self, conn_id) !void` | Park until any stream has data/EOF/new stream/conn closed |
| `sendStreamData` | `(self, conn_id, sid, data, fin) !void` | Queue send; drive task drains |
| `stopSendingRequest` | `(self, conn_id, sid, code) !void` | Queue STOP_SENDING (RFC 9000 §3.5) |
| `openUniStreamRequest` | `(self, conn_id) !u64` | Open a server-initiated uni stream |

Errors: `error.NoConnection` / `error.ConnectionClosed` / `error.Canceled`.

### Handles

```zig
pub const ServerConnection = struct { server: *Server, id: u64 };
pub fn acceptStream(self: ServerConnection) !Stream
pub fn openUniStream(self: ServerConnection) !Stream

pub const Stream = struct { server: *Server, conn_id: u64, id: u64 };
pub fn isUni(self: Stream) bool
pub fn isClientInitiated(self: Stream) bool
pub fn receive(self: Stream, buf: []u8) !usize      // 0 = EOF
pub fn send(self: Stream, data: []const u8, fin: bool) !void
pub fn stopSending(self: Stream, code: u64) !void
```

## `runtime.client.Client`

### `Config`

| Field | Type | Default | Notes |
|---|---|---|---|
| `server_host` | `[4]u8` | `{127,0,0,1}` | Remote IPv4 |
| `server_port` | `u16` | — | Remote port |
| `server_name` | `[]const u8` | `"localhost"` | SNI / certificate name |
| `alpn` | `[]const []const u8` | — | ALPN list |
| `ca_bundle` | `?*const std.crypto.Certificate.Bundle` | `null` | **null = skip cert verification** |
| `insecure_skip_verify` | `bool` | `false` | Also skips verification |
| `version` | `quic_packet.Version` | `.v1` | `.v2` enables v1+v2 |
| `prefer_chacha20` | `bool` | `false` | Prefer ChaCha20-Poly1305 |

### Methods

```zig
pub fn init(allocator, io: std.Io, config: Config) !Client
pub fn connect(self: *Client) !void        // start recv/drive tasks, block until handshake confirmed
pub fn connectWithTimeout(self: *Client, timeout_ms: u32) !void // same handshake, bounded wait; zero is invalid
pub fn send(self: *Client, data: []const u8, fin: bool) !u64     // new bidi stream; returns id
pub fn sendOnStream(self: *Client, sid: u64, data, fin) !void    // send on existing stream
pub fn openStream(self: *Client) !u64      // open bidi stream, no data
pub fn openUniStream(self: *Client) !u64   // open client uni stream (H3 control/QPACK)
pub fn enableH3(self: *Client) void        // poll server uni streams (call before H3 requests)
pub fn initiateKeyUpdate(self: *Client) !void
pub fn receive(self: *Client, sid: u64, buf: []u8) !usize       // blocking read, 0 = EOF
pub fn tryReceiveStreamData(self: *Client, sid: u64, buf) !?usize  // non-blocking
pub fn streamIds(self: *Client, out: []u64) usize
pub fn waitStreamActivity(self: *Client) !void
pub fn close(self: *Client) void           // request APPLICATION_CLOSE
pub fn deinit(self: *Client) void          // stop tasks, free resources
pub fn runEchoSession(self: *Client, payload: []const u8) !bool  // test helper
```

`connectWithTimeout` returns as soon as the handshake completes, including when the client is already connected.
Expiration returns `error.ConnectionTimedOut` without destroying the client or starting another handshake;
the existing driver remains owned by the client until `deinit`.

## `runtime.h3_server.H3Server` / `runtime.h3_client.H3Client`

### H3Server (per-connection driver)

```zig
pub fn init(allocator, server: *Server, conn_id: u64, handler: h3_server.RequestHandler,
            qpack_max_table_capacity: u64, qpack_blocked_streams: u64) H3Server
pub fn deinit(self: *H3Server) void
pub fn run(self: *H3Server) std.Io.Cancelable!void   // serve loop until conn closes/canceled
```

Body > 1 MiB → 413 + STOP_SENDING(H3_EXCESSIVE_LOAD).

### H3Client (single connection)

```zig
pub fn init(allocator, client: *Client, qpack_max_table_capacity: u64, qpack_blocked_streams: u64) H3Client
pub fn deinit(self: *H3Client) void
pub fn run(self: *H3Client) !void          // enableH3 + wait for peer SETTINGS
pub fn sendRequest(self: *H3Client, request: h3_request.Request) !u64
pub fn sendRequestStreamed(self: *H3Client, request: Request, body: h3_request.ResponseBody) !u64
pub fn receiveResponse(self: *H3Client, stream_id: u64) !h3_request.DecodedResponse
pub fn drain(self: *H3Client) !void        // drain server uni streams (decoder ACK catch-up)
```

Typical sequence: `connect` → `H3Client.init` → `run` → `sendRequest`/
`sendRequestStreamed` → `receiveResponse` → optional `drain`.

## `h3_request` types

### `Request`

```zig
pub const Request = struct {
    method: []const u8,                 // required
    path: []const u8,                   // required
    scheme: []const u8 = "https",
    authority: ?[]const u8 = null,
    extra_headers: []const qpack.HeaderField = &.{},
    body: ?[]const u8 = null,           // single contiguous body
};
```

### `Response`

```zig
pub const Response = struct {
    status: u16,                        // required
    extra_headers: []const qpack.HeaderField = &.{},
    body: ?[]const u8 = null,           // single slice → one DATA frame
    body_stream: ?ResponseBody = null,  // takes precedence over body; chunked
};
pub fn isSuccess(self: *const Response) bool  // 2xx
```

### `ResponseBody` (pull iterator)

```zig
pub const ResponseBody = struct {
    ctx: *anyopaque,
    next_fn: *const fn (ctx: *anyopaque, buf: []u8) anyerror!?usize, // null = end; must not block
    deinit_fn: ?*const fn (ctx: *anyopaque) void = null,
    pub fn next(self: ResponseBody, buf: []u8) anyerror!?usize
    pub fn deinit(self: ResponseBody) void
    pub fn fromChunks(allocator, chunks: []const []const u8) !ResponseBody
    pub fn fromRepeating(allocator, byte: u8, total: u64) !ResponseBody
};
```

Chunks are ≤ 8 KiB (`max_response_chunk_payload`), ≤ 8 per stream per pump
(`max_chunks_per_pump`). `deinit` is called by the server when the body is
fully sent or the stream cancelled.

### Decoded types & handler

```zig
pub const DecodedRequest = struct { method: []const u8, path: []const u8, scheme: []const u8,
                                    authority: ?[]const u8, body: ?[]const u8 };   // borrows state-machine buffer
pub const DecodedResponse = struct { status: u16, body: ?[]const u8 };
pub fn isSuccess(self: *const DecodedResponse) bool

// h3/server.zig
pub const RequestHandler = *const fn (req: h3_request.DecodedRequest) h3_request.Response;
```

`qpack.HeaderField = struct { name: []const u8, value: []const u8 }`.

## Coding standards

- `DecodedRequest`/`DecodedResponse` borrow the state machine's buffers; keep
  the stream alive until the response fin is sent.
- All protocol machines are non-blocking; `ResponseBody.next_fn` must never
  block.
- Pass allocators explicitly; prefer `const`; place `defer`/`errdefer`
  immediately after acquisition.
