# quicz API 参考

生产 `runtime` API 与 `h3_request` 类型的参考。所有路径相对 `quicz` 导入根。除非注明，方法为异步阻塞（挂起调用方 async 帧直到操作完成或连接关闭）。

## 顶层命名空间（`src/lib.zig`）

顶层导出约 94 个名字，分三层；大多数应用只接触第一层。

**1. 生产入口** —— 构建 HTTP/3 或 QUIC 应用：

```zig
quicz.runtime                      // { server, client, h3_server, h3_client }
quicz.h3_request                   // Request / Response / ResponseBody / decoded types
quicz.h3_server / quicz.h3_client  // 传输无关的 H3 状态机
quicz.h3 / quicz.qpack / quicz.h3_connection / quicz.h3_limits / quicz.h3_datagram
quicz.webtransport                 // WebTransport session
quicz.Connection / quicz.Config    // 传输层连接 + 配置
quicz.Tls13ClientEndpoint / quicz.Tls13ServerEndpoint   // 握手端点
quicz.Tls13ClientTransport / quicz.Tls13ServerTransport // 每连接传输
quicz.CryptoBackend / quicz.tls13  // TLS 后端面
```

**2. 底层驱动 / 扩展模块** —— 用于自定义事件循环或协议扩展；当 runtime 不适配时可访问：

```zig
quicz.endpoint_types               // Endpoint* 驱动结果/错误类型
quicz.endpoint / quicz.EndpointConnectionLifecycle / quicz.EndpointConnectionRegistry
quicz.protection / quicz.packet / quicz.frame / quicz.recovery   // RFC 9000/9001
quicz.transport_parameters / quicz.transport_error / quicz.address_validation_token
quicz.pacer / quicz.cubic / quicz.pmtu / quicz.gso / quicz.migration / quicz.multipath
quicz.metrics / quicz.session_cache / quicz.connection_pool / quicz.udp_event_loop
quicz.zero_rtt / quicz.lifecycle_options / quicz.buffer / quicz.qlog
```

**3. 原语 / 工具** —— 供以上各层与 interop 测试使用：

```zig
quicz.tls_pem / quicz.pq_kex / quicz.tls13_backend   // TLS 材料 + 后端管线
quicz.duration / quicz.qlog                          // 时间 + qlog 输出
quicz.fuzz_targets / quicz.stress_test               // harness 材料
```

## `runtime.server.Server`

### `Config`

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `port` | `u16` | — | UDP 监听端口（默认 loopback） |
| `alpn` | `[]const []const u8` | — | ALPN 列表，如 `&.{"h3"}` |
| `cert_der` | `[]const u8` | — | DER 证书 |
| `private_key` | `[]const u8` | — | 私钥（`.ecdsa_p256_sha256`；Linux 用 RSA） |
| `prefer_chacha20` | `bool` | `false` | 优先 ChaCha20-Poly1305 |
| `bind_addr` | `?[4]u8` | `null` | 绑定的 IPv4；null = `127.0.0.1`，`.{0,0,0,0}` = 所有 |

固定传输参数：`initial_max_data`/`stream_data` = 10 MiB，bidi/uni 流 = 128，`max_datagram_size` = 8192，空闲超时 = 30s。

### 生命周期

```zig
pub fn init(allocator, io: std.Io, config: Config) !Server
pub fn start(self: *Server) !void              // 幂等；spawn recv+drive tasks
pub fn stop(self: *Server) void                // 置 stopping，唤醒循环
pub fn serve(self: *Server, handler: HandlerFn) !void   // start + spawn 每连接 handler
pub const H3ServeOptions = struct { qpack_max_table_capacity: u64 = 4096, qpack_blocked_streams: u64 = 8 };
pub fn serveH3(self: *Server, options: H3ServeOptions, handler: h3_server.RequestHandler) !void
pub fn deinit(self: *Server) void              // stop + cancel/await drive_group，释放资源
pub const Metrics = struct { active_connections, stream_bytes_sent/received, total_bytes_in_flight, smoothed_rtt_us, rttvar_us, congestion_window, packets_lost, packets_retransmitted }
pub fn metricsSnapshot(self: *Server) Metrics    // 聚合活动连接指标（监控）
pub const HandlerFn = *const fn (ServerConnection) std.Io.Cancelable!void
pub drive_group: std.Io.Group                   // 字段；await 它阻塞直到关闭
```

### 连接 / 流方法（按 `conn_id: u64` 寻址）

| 方法 | 签名 | 语义 |
|---|---|---|
| `accept` | `(self) !ServerConnection` | 阻塞直到下个新连接 |
| `acceptStreamId` | `(self, conn_id) !u64` | 阻塞直到流有数据；连接关闭时 `error.ConnectionClosed` |
| `receiveStreamData` | `(self, conn_id, sid, buf) !usize` | 阻塞读；`0` = EOF |
| `tryAcceptStreamId` | `(self, conn_id) !?u64` | 非阻塞；无则 `null` |
| `tryReceiveStreamData` | `(self, conn_id, sid, buf) !?usize` | 非阻塞；`null`=无数据，`0`=EOF，`n`=字节 |
| `connStreamIds` | `(self, conn_id, out: []u64) usize` | 快照当前接收中的流 id |
| `waitStreamActivity` | `(self, conn_id) !void` | 停泊直到任意流有数据/EOF/新流/连接关闭 |
| `sendStreamData` | `(self, conn_id, sid, data, fin) !void` | 排队发送；drive task 排空 |
| `stopSendingRequest` | `(self, conn_id, sid, code) !void` | 排队 STOP_SENDING（RFC 9000 §3.5） |
| `openUniStreamRequest` | `(self, conn_id) !u64` | 打开 server 发起的 uni 流 |

错误：`error.NoConnection` / `error.ConnectionClosed` / `error.Canceled`。

### 句柄

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

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `server_host` | `[4]u8` | `{127,0,0,1}` | 远端 IPv4 |
| `server_port` | `u16` | — | 远端端口 |
| `server_name` | `[]const u8` | `"localhost"` | SNI / 证书名 |
| `alpn` | `[]const []const u8` | — | ALPN 列表 |
| `ca_bundle` | `?*const std.crypto.Certificate.Bundle` | `null` | **null = 跳过证书校验** |
| `insecure_skip_verify` | `bool` | `false` | 同样跳过校验 |
| `version` | `quic_packet.Version` | `.v1` | `.v2` 启用 v1+v2 |
| `prefer_chacha20` | `bool` | `false` | 优先 ChaCha20-Poly1305 |

### 方法

```zig
pub fn init(allocator, io: std.Io, config: Config) !Client
pub fn connect(self: *Client) !void        // 启动 recv/drive tasks，阻塞直到握手确认
pub fn connectWithTimeout(self: *Client, timeout_ms: u32) !void // 同一握手的有界等待；0无效
pub fn send(self: *Client, data: []const u8, fin: bool) !u64     // 新 bidi 流；返回 id
pub fn sendOnStream(self: *Client, sid: u64, data, fin) !void    // 在已有流上发送
pub fn openStream(self: *Client) !u64      // 打开 bidi 流，无数据
pub fn openUniStream(self: *Client) !u64   // 打开 client uni 流（H3 control/QPACK）
pub fn enableH3(self: *Client) void        // 轮询 server uni 流（H3 请求前调用）
pub fn initiateKeyUpdate(self: *Client) !void
pub fn receive(self: *Client, sid: u64, buf: []u8) !usize       // 阻塞读，0 = EOF
pub fn tryReceiveStreamData(self: *Client, sid: u64, buf) !?usize  // 非阻塞
pub fn streamIds(self: *Client, out: []u64) usize
pub fn waitStreamActivity(self: *Client) !void
pub fn close(self: *Client) void           // 请求 APPLICATION_CLOSE
pub fn deinit(self: *Client) void          // 停止 tasks，释放资源
pub fn runEchoSession(self: *Client, payload: []const u8) !bool  // 测试辅助
```

## `runtime.h3_server.H3Server` / `runtime.h3_client.H3Client`

### H3Server（每连接驱动）

```zig
pub fn init(allocator, server: *Server, conn_id: u64, handler: h3_server.RequestHandler,
            qpack_max_table_capacity: u64, qpack_blocked_streams: u64) H3Server
pub fn deinit(self: *H3Server) void
pub fn run(self: *H3Server) std.Io.Cancelable!void   // serve 循环直到连接关闭/取消
```

body > 1 MiB → 413 + STOP_SENDING(H3_EXCESSIVE_LOAD)。

### H3Client（单连接）

```zig
pub fn init(allocator, client: *Client, qpack_max_table_capacity: u64, qpack_blocked_streams: u64) H3Client
pub fn deinit(self: *H3Client) void
pub fn run(self: *H3Client) !void          // enableH3 + 等待对端 SETTINGS
pub fn sendRequest(self: *H3Client, request: h3_request.Request) !u64
pub fn sendRequestStreamed(self: *H3Client, request: Request, body: h3_request.ResponseBody) !u64
pub fn receiveResponse(self: *H3Client, stream_id: u64) !h3_request.DecodedResponse
pub fn drain(self: *H3Client) !void        // 排空 server uni 流（decoder ACK 追平）
```

典型时序：`connect` → `H3Client.init` → `run` → `sendRequest`/`sendRequestStreamed` → `receiveResponse` → 可选 `drain`。

## `h3_request` 类型

### `Request`

```zig
pub const Request = struct {
    method: []const u8,                 // 必填
    path: []const u8,                   // 必填
    scheme: []const u8 = "https",
    authority: ?[]const u8 = null,
    extra_headers: []const qpack.HeaderField = &.{},
    body: ?[]const u8 = null,           // 单一连续 body
};
```

### `Response`

```zig
pub const Response = struct {
    status: u16,                        // 必填
    extra_headers: []const qpack.HeaderField = &.{},
    body: ?[]const u8 = null,           // 单一切片 → 一个 DATA 帧
    body_stream: ?ResponseBody = null,  // 优先于 body；分块
};
pub fn isSuccess(self: *const Response) bool  // 2xx
```

### `ResponseBody`（pull 迭代器）

```zig
pub const ResponseBody = struct {
    ctx: *anyopaque,
    next_fn: *const fn (ctx: *anyopaque, buf: []u8) anyerror!?usize, // null = 结束；不得阻塞
    deinit_fn: ?*const fn (ctx: *anyopaque) void = null,
    pub fn next(self: ResponseBody, buf: []u8) anyerror!?usize
    pub fn deinit(self: ResponseBody) void
    pub fn fromChunks(allocator, chunks: []const []const u8) !ResponseBody
    pub fn fromRepeating(allocator, byte: u8, total: u64) !ResponseBody
};
```

块 ≤ 8 KiB（`max_response_chunk_payload`），每次 pump 每流 ≤ 8 块（`max_chunks_per_pump`）。body 完全发送或流取消时 server 调用 `deinit`。

### 解码类型 & handler

```zig
pub const DecodedRequest = struct { method: []const u8, path: []const u8, scheme: []const u8,
                                    authority: ?[]const u8, body: ?[]const u8 };   // 借用状态机缓冲
pub const DecodedResponse = struct { status: u16, body: ?[]const u8 };
pub fn isSuccess(self: *const DecodedResponse) bool

// h3/server.zig
pub const RequestHandler = *const fn (req: h3_request.DecodedRequest) h3_request.Response;
```

`qpack.HeaderField = struct { name: []const u8, value: []const u8 }`。

## 编码规范

- `DecodedRequest`/`DecodedResponse` 借用状态机缓冲；保持流存活直到响应 fin 发出。
- 所有协议机器非阻塞；`ResponseBody.next_fn` 绝不得阻塞。
- 显式传 allocator；优先 `const`；`defer`/`errdefer` 紧随资源获取之后。
