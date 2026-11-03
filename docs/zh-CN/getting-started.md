# quicz 快速上手

本指南带你用 quicz 的生产 I/O 运行时（`std.Io` 异步 + QUIC 流模型）构建真实的客户端/服务端应用。覆盖 HTTP/3 路径（大多数应用推荐）、自定义流协议，以及高级模式（DATAGRAM、0-RTT、服务端推送、WebTransport）。

quicz 暴露四层 API——开箱 HTTP/3、运行时传输、TLS 端点、sans-IO 核心。本指南用最上面两层；底层见 [API 分层](api-layers.md)（含与 s2n-quic / quic-go / quinn / quiche / msquic / quic-zig 对照）。

前置：Zig 0.17.0。库使用纯 Zig，没有 C 库依赖。

## 1. 添加依赖

```bash
zig fetch --save git+https://github.com/venjiang/quicz
```

在你的 `build.zig`：

```zig
const quicz_dep = b.dependency("quicz", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("quicz", quicz_dep.module("quicz"));
```

然后导入：

```zig
const quicz = @import("quicz");
```

## 2. 通用设置：事件循环

server 与 client 都运行在 Zig `std.Io` 实例上。`Threaded` 后端在线程池上执行异步 I/O；你的应用从一个或多个异步任务驱动流。

```zig
var threaded = std.Io.Threaded.init(allocator, .{});
defer threaded.deinit();
const io = threaded.io();
```

## 3. HTTP/3 服务端

`runtime.Server` 持有 socket、端点与连接生命周期。用 `serveH3` 配合同步请求 handler。

```zig
const Server = quicz.runtime.server.Server;

// Handler：接收完全解码的请求，返回 Response。
fn handleRequest(req: quicz.h3_request.DecodedRequest) quicz.h3_request.Response {
    if (std.mem.eql(u8, req.path, "/")) {
        return .{ .status = 200, .body = "Hello from quicz HTTP/3!" };
    }
    // 流式（分块）响应体——作为多个 DATA 帧发送
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
    .cert_der = &certificate_der,   // DER 证书
    .private_key = &server_private_key, // 匹配的私钥
});
defer server.deinit();
try server.serveH3(.{}, handleRequest); // 选项：qpack_max_table_capacity, qpack_blocked_streams

// 阻塞直到被杀死（serveLoop 作为并发 task 运行）
server.drive_group.await(io) catch {};
```

用 `curl --http3-prior https://127.0.0.1:4433/ -k -v` 测试（需支持 HTTP/3 的 curl 构建）。

### 响应变体

| 字段 | 含义 |
|---|---|
| `.body = slice` | 单一连续 body，编码为一个 DATA 帧 |
| `.body_stream = ResponseBody` | 分块 body（优先于 `body`） |
| 两者皆无 | 无 body 响应（HEADERS + fin） |

### 请求体

服务端把请求 DATA 帧聚合到 `max_request_body_size`（默认 1 MiB）。handler 内 `req.body` 持有完整聚合请求体（或 `null`）。超大请求体以 413 + STOP_SENDING 拒绝。

## 4. HTTP/3 客户端

```zig
const Client = quicz.runtime.client.Client;
const H3Client = quicz.runtime.h3_client.H3Client;

var client = try Client.init(allocator, io, .{
    .server_port = 4433,
    .server_name = "localhost",
    .alpn = &.{"h3"},
    .insecure_skip_verify = true, // ca_bundle 为 null 也跳过校验
});
defer client.deinit();
try client.connect();

var h3cli = H3Client.init(allocator, &client, 4096, 8); // qpack cap, blocked streams
defer h3cli.deinit();
try h3cli.run(); // 等待服务端 SETTINGS

// 发 GET 请求
const stream = try h3cli.sendRequest(.{
    .method = "GET",
    .path = "/",
    .authority = "localhost",
});
const resp = try h3cli.receiveResponse(stream);
if (resp.isSuccess()) {
    // resp.body 是聚合响应体（或 null）
}
client.close();
```

### 流式请求体

大上传用 `sendRequestStreamed` 以有界 DATA 帧发送 body，阻塞直到完全排空（等待流控额度）：

```zig
const body = try quicz.h3_request.ResponseBody.fromRepeating(allocator, 'A', 20 * 1024);
const stream = try h3cli.sendRequestStreamed(.{
    .method = "POST",
    .path = "/echo",
    .authority = "localhost",
}, body);
const resp = try h3cli.receiveResponse(stream);
```

## 5. 底层流 echo（自定义协议）

非 HTTP 协议用 `Server.serve` + 每连接 handler（std.http 模型）。每连接一个 handler task。

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

客户端 `connect()` 后流上 `send`/`receive`：

```zig
try client.connect();
const sid = try client.send("hello", false);
var buf: [4096]u8 = undefined;
const n = try client.receive(sid, &buf); // 0 = EOF
```

## 6. 证书

示例内置本地测试用 P-256 密钥对（见任意 `examples/*_loopback.zig`）。生产：

- **macOS / arm64**：ECDSA P-256 证书可用。
- **Linux x86_64**：Zig 0.16 的 `std.crypto` 对 P-256/P-384/Ed25519 签名验证有已知代码生成 bug。用 **RSA 证书** + **Release** 构建（`-Doptimize=fast`）。OpenSSL 生成的 RSA 证书在 Linux 上验证正确。

`Server.Config` 支持 `bind_addr`（默认 `127.0.0.1`）；设 `.{0,0,0,0}` 监听所有接口。

## 7. 常见模式

- **每连接 handler task**：`Server.serve`/`serveH3` 每连接 spawn 一个 task；每连接资源单 owner（无引用计数）。
- **非阻塞多流**：handler 服务多流时，用 `tryAcceptStreamId` / `tryReceiveStreamData` / `connStreamIds` 轮询，并在 `waitStreamActivity` 停泊，而非阻塞在单流上。
- **并发**：`std.Io.Group.concurrent` 运行独立 client/server task；见 `examples/multi_client_bench.zig`（N 并发客户端）。

## 8. 高级模式

### 服务端 → 客户端单向推送

服务端可开单向流并推送数据给客户端读（连接上 `openUniStream`；客户端 `openUniStream`/`sendOnStream`）。客户端需 `enableH3()` 开启服务端单向流轮询，drive task 才会投递它们。

```zig
// server handler
var push = try conn.openUniStream();          // server 发起的 uni 流
try push.send("server push payload", true);   // fin

// client
try client.enableH3();                        // 轮询服务端 uni 流
// ... connect 之后；推流是 client 读的 id
```

### 多客户端并发

`std.Io.Group.concurrent` 对单 server 运行 N 个独立客户端；每个客户端是独立 `runtime.Client`（自己的 drive task），跨核并行。见 `examples/multi_client_bench.zig`（并发握手 + 聚合吞吐）与 `examples/stability_bench.zig`（长稳泄漏检查）。

### DATAGRAM、0-RTT、WebTransport、底层驱动

这些在底层 API 层（见 [API 分层](api-layers.md)），而非运行时的流 API：

- **DATAGRAM（RFC 9221）**：sans-IO 核心上的不可靠应用消息（`Connection` datagram 方法 + `h3_datagram`）。可运行：`examples/datagram_echo.zig`（`DATAGRAM Throughput`）。
- **0-RTT**：经 `Tls13ClientEndpoint` + `session_cache` 的会话恢复 early data；不含运行时 socket 循环。可运行：`examples/zero_rtt_echo.zig`、`examples/udp_zero_rtt_loopback.zig`。
- **WebTransport**：`src/h3/webtransport.zig` 在 `h3_connection` 上构建 WebTransport 会话（extended CONNECT）。
- **sans-IO 驱动**：`Connection` + `endpoint_types` + `EndpointConnectionLifecycle`——喂数据报、轮询输出，无 TLS/socket。见 `examples/interop_event_loopback.zig` 与 `examples/udp_*_loopback.zig` 系列；`examples/udp_path_validation_loopback.zig`（连接迁移 + 路径验证）与 `examples/udp_key_update_loopback.zig`（key update）最丰富。

## 另见

- `docs/en/api-layers.md` — 高/低层映射 + 与其它库对照。
- `docs/en/api-reference.md` — 完整签名参考。
- `docs/en/architecture.md` — 内部设计。
- `examples/h3_runtime_loopback.zig`、`examples/io_echo.zig`、`examples/multi_client_bench.zig` — 可运行示例。
