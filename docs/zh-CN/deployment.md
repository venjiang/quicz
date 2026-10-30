# 部署指南

本指南讲解 quicz 的生产部署：HTTP/3 服务路径、TLS 证书、水平扩展、监控、已知限制与故障排查。前提：库能干净构建，且 [getting-started.md](getting-started.md) 的示例可运行。

## 1. 运行时入口

生产路径是 `runtime.Server`（`std.Io.Threaded`）。

- **HTTP/3** — `server.serveH3(options, handleRequest)` 在一个进程内驱动传输层、endpoint、连接生命周期与 H3/QPACK 驱动。这是服务的推荐入口。
- **自定义流** — `server.serve(handler)` 提供每连接的双向流访问（`ServerConnection.acceptStream` + `Stream.receive/send`），用于非 HTTP 协议。

```zig
var server = try Server.init(allocator, io, .{
    .port = 4433,
    .alpn = &.{"h3"},
    .cert_der = cert_der,
    .private_key = private_key,
    .bind_addr = .{0, 0, 0, 0}, // 接受远程客户端
    // .max_connections = 4096, // 默认；设为你预期的峰值 + 余量
});
defer server.deinit();
try server.serveH3(.{}, handleRequest);
```

## 2. TLS 证书

- **Linux x86_64** — 使用 **RSA** 证书。Zig 0.16 `std.crypto` 在 x86_64 有 P-256/P-384/Ed25519 签名验证代码生成 bug，ECDSA 证书在那里校验证失败。RSA-PSS SHA256/384/512（标准 TLS 1.3 参数：MGF1 = hash、salt = hash）验证正常。
- **aarch64 Linux 与 macOS** — ECDSA P-256 正常。
- 证书是 DER 编码的 X.509 叶证书；私钥对 ECDSA 是原始 P-256 标量（32 字节）。用 `openssl` 生成并加载 DER 字节（见 `run_external_interop.sh` 中 `examples/interop/testdata/` 的生成器）。

## 3. 端口与绑定

- `Server.Config.bind_addr` 默认 `127.0.0.1`。设 `.{0,0,0,0}` 接受远程客户端（跨主机部署）。
- QUIC 是 UDP。在防火墙/负载均衡开放 UDP 端口；不要用 TCP 反向代理映射。

## 4. 水平扩展

每个 `Server` 运行一个 drive 任务，串行处理所有已接受连接（与 s2n-quic / quiche / quic-zig 相同的单线程事件循环模型）。要在多核上扩展聚合吞吐，运行**多个 Server 实例**：

- 在不同 UDP 端口，由负载均衡按客户端连接 ID（或源 IP）哈希到固定后端，**或**
- 同端口 + `SO_REUSEPORT`（需手动建 socket；Zig `std.Io.net.IpAddress.bind` 目前不设 REUSEPORT）。

按连接 ID 负载均衡，让一个连接粘住一个后端（QUIC 连接在没有连接迁移时不能跨后端迁移）。

## 5. 监控

- `Server.metricsSnapshot()` 一次调用聚合所有活动连接指标：流字节收发、in-flight、平滑 RTT/RTTVAR、拥塞窗口、累计丢包/重传（`Connection.connectionStats()` 提供每连接同构数据）。从 metrics 端点暴露它，对丢包率或 RTT 尖峰告警。
- runtime 通过 `std.log`（`quicz_runtime` 作用域）记录连接 accept/close 与 drive 错误。关闭连接上的 `error.UnknownConnectionId` 是对已回收连接的重传，属良性，不是故障。

## 6. 已知限制

- **出站包大小** — `send_mtu`（默认 1350，标准 MTU）限制出站 QUIC 包，接收路径保留 8192 字节余量。生产不要调高：jumbo 数据报在真实网络会 IP 分片，且（在 loopback）会把 RTT 采样推高成拥塞/pacing 正反馈，可能让连接停滞。见 production_tuning.md。
- **Linux x86_64 std.crypto bug** — 用 RSA 证书（见 §2）。
- **loopback/容器高吞吐长跑** — 持续传输（> ~90 秒）在 loopback 或容器网络上会因 socket 排队推高 RTT 采样、pacer 跟随而渐进变慢。这是无损高吞吐路径的平台特性，不是逻辑 bug；真实网络（正常 RTT）不受影响。CI 短时稳定性运行（60 秒）低于受影响区间。

## 7. 故障排查

- **对严格客户端握手失败**：检查证书链完整（CA + 叶，非截断 DER）且 ALPN 匹配。quicz 容忍不支持的 TLS key-share group 与无 PSK 的 early_data（RFC 8446 §4.2.8 / RFC 9001 §4.5），所以不是这些原因。
- **持续传输后连接停滞**：用 `connectionStats` 查每连接 RTT 与丢包；若在 loopback/容器路径 RTT 攀升，见 §6（平台特性）。真实网络上调 `max_idle_timeout_ms` 匹配你的保活需求。
- **对第三方 H3 客户端互通失败**：quicz 实现 RFC 9204 QPACK 静态表与 4 位字面名前缀；错误的表或前缀是早期互通失败的根因，已被 CI 的 HTTP/3 互通步骤覆盖。
- **interop 矩阵 `AddressInUse`**：残留 server 进程占 UDP 端口；CI 脚本在 case 间清扫。

## 8. 部署前验证

- `zig build test --summary all` — 1883 单元测试。
- `zig build run-stability-bench -- 60000` — 持续传输，无错误/泄漏。
- `zig build run-h3-runtime-loopback -Doptimize=fast` — 真实握手 + H3/QPACK 往返。
- CI（`.github/workflows/ci.yml`）跑单元测试、跨实现互通矩阵（quic-go / quiche / s2n-quic，正向 + 反向）、双向 HTTP/3 互通（go quic-go）、fuzz 回归与稳定性守卫。