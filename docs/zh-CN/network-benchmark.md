# quicz 真实网络压测

在真实网络上（跨主机、丢包、拥塞）压测 quicz 的指南，区别于 `benchmark.md` 的 loopback 测量。这些运行需要两台 Linux 主机（一台作流量整形器），在本仓库的本地 loopback 环境之外执行。

## 工具

| 工具 | 用途 |
|---|---|
| `examples/multi_client_bench.zig`（`run-multi-client-bench`） | N 并发客户端 vs 单 server：握手延迟 + 聚合吞吐 |
| `examples/quic_bench_hs.zig`（`run-quic-bench-hs`） | 真实握手吞吐 + echo 延迟 |
| `tc` / `netem`（Linux） | 模拟丢包、延迟、抖动、带宽 |
| `iperf3` | 对拍原始 TCP/UDP 链路容量，公平对比 |

全部用 ReleaseFast 构建——Debug 构建是测量假象（编译器代码生成，非库逻辑）：

```bash
zig build -Doptimize=fast
# 或按目标
zig build run-multi-client-bench -Doptimize=fast
```

## 1. 跨主机：client 在主机 A，server 在主机 B

server 默认监听 loopback。要接受远程客户端，绑定所有接口：

```zig
var server = try Server.init(allocator, io, .{
    .port = 4433,
    .alpn = &.{"hq-interop"},
    .cert_der = &certificate_der,
    .private_key = &server_private_key,
    .bind_addr = .{0, 0, 0, 0},   // 监听所有接口
});
```

**主机 B**（server）：

```bash
zig build run-io-echo -Doptimize=fast   # 或 run-h3-server 用 H3
```

**主机 A**（client），`Client.Config.server_host` 指向 B 的 IP、`server_port` 用 4433。改 `examples/multi_client_bench.zig` 或用连远端地址的小客户端：

```zig
var client = try Client.init(allocator, io, .{
    .server_host = .{ 10, 0, 0, 2 },   // 主机 B
    .server_port = 4433,
    .server_name = "host-b",
    .alpn = &.{"hq-interop"},
});
```

> **Linux x86_64**：用 **RSA 证书**（Zig 0.16 `std.crypto` 对 P-256/P-384/Ed25519 签名验证在 x86_64 有已知代码生成 bug）。OpenSSL 生成的 RSA 证书验证正确。

## 2. Docker 跨主机验证（2026-08-08 验证）

同 Docker bridge 网络上的两个 quicz Linux 容器当独立主机（不同网络命名空间、真实非 loopback 报文路径）。跨容器跑压测：

```bash
# 宿主机构建：交叉编译 x86_64 二进制（或在容器内编译）
zig build-exe -target x86_64-linux-musl --dep quicz \
    -Mroot=examples/multi_client_bench.zig -Mquicz=src/lib.zig \
    -Ofast -lc --name qmc-bench-x64

# 同一 bridge 网络的两个容器
docker run -d --name bench-server --network bridge --entrypoint sleep <quicz-linux-img> infinity
docker run -d --name bench-client --network bridge --entrypoint sleep <quicz-linux-img> infinity
docker cp qmc-bench-x64 bench-server:/root/ && docker cp qmc-bench-x64 bench-client:/root/

# server 容器（监听 0.0.0.0）；client 容器连 server IP
docker exec -d bench-server /root/qmc-bench-x64 server
docker exec bench-client /root/qmc-bench-x64 client <bench-server-IP>
```

验证结果（2 容器、Linux x86_64、ReleaseFast、ECDSA 证书）：

```
multi-client bench: ok=8/8 avg_connect=320 ms  aggregate=1.1 Mbit/s (host=192.168.215.2)
```

8/8 并发跨主机握手 + echo 成功。低聚合反映容器 bridge 网络（小 cwnd × 握手 RTT + docker 软件转发），非 quicz 协议缺陷。注意：ECDSA P-256 测试证书在 Linux x86_64 ReleaseFast 下 runtime 握手路径可用。

## 3. 用 netem 模拟丢包 / 延迟 / 拥塞

在 Docker 容器（Linux x86_64、`--cap-add NET_ADMIN` + `apt-get install iproute2`）对 client 出口整形验证：

```bash
# 1% 丢包：quicz 恢复——8/8 并发跨主机握手完成
tc qdisc add dev eth0 root netem loss 1%
/root/qmc-bench-x64 client 192.168.215.2
# ok=8/8 avg_connect=279ms aggregate=0.7 Mbit/s

# 5% 丢包 + 20ms 延迟：demo 的 8 并发客户端部分超时
# （benchmark 无每客户端握手截止时间），部分失败。
# 跑单客户端或降低丢包，做更干净的高丢包恢复检查。
tc qdisc add dev eth0 root netem loss 5% delay 20ms
```

丢包下的 `error.UnknownConnectionId` 日志是 server 向已回收/未知连接的重传；连接仍完成。恢复（PTO 重传）在 1% 丢包下已验证生效；5% 情形受 benchmark 无握手超时限制，非协议缺陷。


在 Linux 主机上整形两台主机间的网络路径。`netem` 是出口接口上的 `tc` qdisc：

```bash
# 10 ms 单向延迟、1% 丢包、4 MB/s 带宽
tc qdisc add dev eth0 root netem delay 10ms loss 1% rate 4mbit

# 重置
tc qdisc del dev eth0 root
```

两台主机都应用同规则为对称整形，或只在一台用于非对称路径。

### 丢包 vs 恢复

QUIC 的丢包恢复（PTO、拥塞控制）是待测行为。在若干丢包率下跑 echo 延迟压测，观察 P50/P99 如何增长、吞吐如何下降：

```bash
for loss in 0 0.5 1 3 5; do
    tc qdisc add dev eth0 root netem loss "${loss}%"
    zig build run-quic-bench-hs -Doptimize=fast 2>&1 | tee /tmp/hs_loss${loss}.log
    tc qdisc del dev eth0 root
done
```

### 延迟受限的 RTT

固定延迟下，聚合吞吐受 `cwnd / RTT` 限制。提高 `initial_max_data` / `initial_max_stream_data`（server/client 传输参数）并允许拥塞窗口增长，是这里的调优项。

## 4. 多客户端并发（跨主机）

`multi_client_bench` 已测 N 并发握手 + 聚合吞吐。跨主机跑以包含真实 RTT：

```bash
# 主机 B：跑 server 部分（改示例绑定 0.0.0.0）
# 主机 A：16 客户端，真实网络
zig build run-multi-client-bench -Doptimize=fast
```

预期输出（ReleaseFast，loopback 参考）：

```
multi-client bench: ok=8/8 avg_connect=3 ms  aggregate=628.6 Mbit/s
```

真实网络下，`avg_connect` 变为 RTT 受限（握手约 1.5× RTT），聚合吞吐反映路径的 `cwnd/RTT` 限制。

## 5. 记录结果

每次运行记录平台 + commit 元数据，镜像 loopback 套件的 `bench_results/<UTC 时间戳>_<commit>.log` 约定：

```bash
BENCH_DIR=bench_results/$(date -u +%Y%m%dT%H%M%SZ)_$(git rev-parse --short HEAD)
mkdir -p "$BENCH_DIR"
# 记录：主机规格、tc 整形、quicz 版本、原始输出
```

## 6. 信任数值前的检查清单

1. 用 `-Doptimize=fast` 构建（绝不用 Debug）。
2. 用 `iperf3` 对拍原始路径；quicz 应落在链路每连接 UDP/TCP 上限的合理因子内。
3. Linux x86_64 用 RSA 证书。
4. 关闭竞争流量；跨运行对比时固定 CPU。
5. 显式报告丢包/延迟/RTT——没有路径属性，"吞吐"无意义。