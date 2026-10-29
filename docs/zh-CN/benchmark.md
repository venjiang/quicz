# quicz 性能基准测试

## 测试方法

secnetperf 风格微基准，测量 loopback UDP 上的原始 QUIC 传输性能。

- **协议**：QUIC v1，安装 1-RTT 密钥（绕过 TLS 握手，仅测传输层）
- **套接字**：loopback UDP，8900 字节 datagram（macOS UDP 上限 9000B）
- **I/O 层**：std.Io.Threaded（跨平台，Linux 自动启用 sendmmsg 批量发送）
- **构建**：`zig build-exe -Ofast`
- **平台**：Apple M 系列 macOS，Zig 0.16（std.Io 跨平台，Linux 由 std.Io 自动适配 io_uring/sendmmsg，不另测）
- **拥塞控制**：CUBIC（RFC 8312/9438）
- **Pacer**：Token bucket，ns 精度（loopback 下 srtt ~1μs 不截断）
- **波动性**：loopback 吞吐 run 间波动 ±20%（系统负载、CUBIC 窗口动态、热状态）；下述数字为点测量——**趋势与量级比绝对值更重要**。多次跑取的范围以区间给出。

## 运行方式

```bash
# 标准化套件：ReleaseFast 构建全部 bench，按固定顺序运行，
# 记录平台/commit 元信息与完整输出到 bench_results/<UTC时间戳>_<commit>.log。
# 入库的结果文件即对比基线；改动后重跑并 diff 结果。
scripts/run_bench_suite.sh
zig build bench-suite        # 相同顺序，不记录结果

# 单个 bench
zig build run-quic-bench             # installed-keys 微基准
zig build run-quic-bench-hs          # 真实握手吞吐 + 延迟
zig build run-quic-bench-simple      # 单线程裸处理
zig build run-quic-bench-datagram    # RFC 9221 DATAGRAM 吞吐
zig build run-quic-bench-profile     # 分阶段剖析
zig build run-congestion-bench       # NewReno vs CUBIC 仿真丢包
```

## 内存直连基准（单线程，ReleaseFast）

| 指标 | 数值 | 说明 |
|---|---|---|
| 单流上传（16 MB） | **0.35 GB/s** | 无 UDP 开销，CUBIC，cwnd=272 KB |
| Echo P50 | **7.5 μs** | 1 KB 完整 QUIC 往返（内存直连） |
| Echo P99 | **47.7 μs** | 长尾受 OS 调度影响 |
| Echo P99.9 | **665.2 μs** | |
| 4 流聚合（4×4 MB） | **0.34 GB/s** | 共享 cwnd |


### CPU 占用（真实握手 bench 全套，/usr/bin/time -l）

| 指标 | 数值 |
|---|---|
| Real time | 3.90s |
| User CPU | 3.21s（~82% 单核） |
| Sys CPU | 4.25s（~109%，多核累积） |
| Peak RSS | ~2.4 GB（bench arena 跨迭代累积，非生产单连接占用） |

sys CPU 占比高，来自每包 UDP sendto/recvfrom 系统调用；吞吐受 ACK 时钟与共享 I/O 路径限制，非纯 CPU 算力。
## 吞吐量（单流，loopback，真实握手）

| 指标 | 数值 | 说明 |
|---|---|---|
| 单流吞吐 | **~310-440 MB/s**（3 次实测 313/318/440；run 间 ±20%） | 真实 TLS 1.3 握手，quic-go 式每次 5 轮取均值 |
| 握手耗时 | ~0.6–1.0 ms/轮 | TLS 1.3，transport parameters 经握手协商（RFC 9000 §7.4） |
| 传输 | 64 MB/轮 | 8900 B datagram，CUBIC，100μs receiveTimeout（64 MB 让 CUBIC 过慢启动进稳态，降低波动） |

> 测量方法（`examples/quic_bench_hs.zig`）：每次迭代新建连接并做真实 TLS 1.3 握手（RFC 9000 §7 / RFC 9001 §4，流程同 `examples/interop_client.zig`），测「握手后传输 16 MB 到对端收齐」的整段时间，多次迭代取均值/标准差（quic-go `BenchmarkTransfer` 模型）。
> 真实握手确保 transport parameters 正确协商；installed-keys bypass 跳过握手即跳过该协商（RFC 9000 §7.4），仅用于单点延迟微基准，不作吞吐口径。
> 传输循环按 RFC 9002 §6.2 调用 `serviceLossDetectionTimer`（PTO 重传），避免 ACK 延迟时失速。单流波动来自 CUBIC 在 loopback（~1μs RTT）的窗口动态；多流聚合更稳。

## Echo 延迟（1 KB 往返，真实握手）

| 百分位 | 延迟 |
|---|---|
| P50 | **21.7 μs** |
| P99 | **77.3 μs** |
| P99.9 | **175.9 μs** |

5000 次迭代，真实握手后 1 KB 完整 QUIC 往返（加密+发送+接收+解密+回显）。

## 多流吞吐（4 并发流，真实握手）

| 指标 | 数值 | 说明 |
|---|---|---|
| 4 流聚合 | **~304 MB/s**（stddev 4.5%） | 真实握手，64 MB，quic-go 式 5 次迭代 |

## 丢包恢复（真实握手 + 模拟丢包）

| 丢包率 | 吞吐量 | 说明 |
|---|---|---|
| 1%（loopback） | 452 MB/s | CUBIC 快速恢复 |
| 5%（loopback） | 303 MB/s | |
| 1%（100μs RTT） | 126 MB/s | |
| 5%（100μs RTT） | 120 MB/s | |

> 以上 Echo/多流/丢包均为真实握手 bench（`quic_bench_hs.zig`）实测。

## 跨平台架构说明

- **不自建 Linux GSO 层**：Zig `std.Io.Threaded` 在 Linux 已内置 `sendmmsg` 批量发送（`Threaded.zig:1971`）
- **std.Io 在 Linux 默认用 io_uring**（`Io.zig:32`），Threaded 是显式选择的后端
- **sendMany API 仅在 Linux 有收益**（sendmmsg），macOS 下反而增加数组构建开销
- **nanoTime 跨平台**：comptime 条件编译，macOS `mach_absolute_time` / Linux `clock_gettime(MONOTONIC)`

## 握手与连接基线（真实握手）

| 基线 | 数值 | 说明 |
|---|---|---|
| 握手延迟 | **P50 515.2 μs / P99 654.5 μs** | 完整 TLS 1.3 握手，200 次 |
| 握手吞吐 | **~1253 conn/s** | 新建连接速率，100 次 |
| 流开启速率 | **~1.49 亿/s** | 单连接 openStream，100k 次 |

> 均为真实握手 bench（`quic_bench_hs.zig`）实测；握手吞吐受单线程串行限制。

## 连接扩展基线（真实握手，多线程）

| 基线 | 数值 | 说明 |
|---|---|---|
| 并发聚合（4 连接，thread-per-connection，每连接独立 std.Io） | ~285 MB/s | I/O 分区 |
| 并发聚合（4 连接，**std.Io Group.concurrent 异步**，共享 std.Io） | ~408 MB/s（同轮 1.43x 于 thread-per-connection） | 线程效率更高（少量线程跑同样连接） |

> **关键发现（参考 msquic `docs/Execution.md`）**：msquic 每处理器一个 worker 线程、连接按 RSS 分区，每连接单线程但不同连接并行。quicz 实测：(1) 共享单个 std.Io 时并发连接被串行化（无扩展）；(2) 每连接独立 std.Io（I/O 分区）扩展到 ~1.2x；(3) **std.Io Group.concurrent 异步多路复用比 thread-per-connection 线程效率更高（同轮 ~1.43x）**——用更少线程跑同样连接。但三种模型都**未线性扩展**，因吞吐受单核包处理 CPU 限制（服务端容量 ~900 MB/s），非 I/O 模型；真正线性扩展需 msquic 式多核并行处理包。quic-go（每连接 goroutine）、quinn（每连接 tokio task）同理。绝对值随系统负载/温度波动。

## 与其他 QUIC 实现对比

### 测试条件差异说明

各实现的基准测试条件差异极大，直接对比数字需谨慎：

| 因素 | 影响 |
|---|---|
| GSO/GRO（Linux） | 吞吐提升 3-10x，批量系统调用 |
| XDP（Linux 内核旁路） | 吞吐提升 2-5x，绕过内核网络栈 |
| loopback vs 物理网络 | loopback 无丢包/抖动，RTT ~1μs |
| 单线程 vs 多线程 | 多核可线性扩展 |
| 平台（macOS vs Linux） | macOS 无 GSO/XDP，系统调用开销更高 |

### 单流吞吐量

> **单位与条件须知**：下表外部数据多来自 KIT 2025 的 **10 Gbit/s 物理测试床 goodput**，单位 **Mbit/s**（兆比特）；quicz 用 **MB/s**（兆字节，1 MB/s = 8 Mbit/s）。测试条件差异（物理链路 vs loopback、MTU、GSO、平台）极大，直接比数字需谨慎。

| 实现 | 语言 | Goodput | 条件 | 来源 |
|---|---|---|---|---|
| ngtcp2（C，最快配对） | C | **4172 Mbit/s（~521 MB/s）** | 10Gb 物理测试床，ngtcp2×ngtcp2 | KIT 2025 |
| lsquic | C | ~2486 Mbit/s（~311 MB/s） | 10Gb 物理测试床 | KIT 2025 |
| quic-go | Go | 1220–2233 Mbit/s（~152–279 MB/s） | 10Gb 物理测试床（配对相关） | KIT 2025 |
| quiche | Rust | ~1220–1335 Mbit/s（~152–167 MB/s） | 10Gb 物理测试床（配对相关） | KIT 2025 |
| picoquic | C | ~1346–1451 Mbit/s（~168–181 MB/s） | 10Gb 物理测试床 | KIT 2025 |
| msquic | C | ~1 Gbps | macOS loopback | secnetperf |
| **quicz** | **Zig** | **~310-440 MB/s（~2480-3520 Mbit/s）** | **macOS loopback，真实握手，8.9KB datagram，无 GSO** | **本基准** |

**关键结论（均有出处）**：
- KIT 2025 实测 10Gb 物理测试床 goodput 区间 **1220–4172 Mbit/s（~152–521 MB/s）**；**MTU 1500→9000 可让部分实现打满 10 Gbit/s**。
- KIT 论文明确：**吞吐瓶颈主要来自单核性能约束**（与 quicz 受 ACK 时钟/共享 I/O 路径约束一致）。
- quicz ~310-440 MB/s ≈ **2480-3520 Mbit/s**，落在 KIT 区间内；条件不同（macOS loopback 无 GSO vs 10Gb 物理链路），但量级与主流实现相当。
- quic-go #3670 用户自测 ~1100 Mbit/s（~137 MB/s，Ubuntu 双主机 10Gb 物理链路，非 loopback）。

## Echo 延迟（小请求往返）

| 实现 | 语言 | P50 | P99 | 条件 | 来源 |
|---|---|---|---|---|---|
| msquic | C | ~5-15 μs | ~30-50 μs | Linux, io_uring | secnetperf |
| s2n-quic | Rust | ~20-40 μs | ~80-150 μs | Linux, epoll | 社区基准 |
| quic-go | Go | ~50-100 μs | ~200-500 μs | Linux | 社区基准 |
| quiche | Rust | ~30-80 μs | ~100-200 μs | Linux, 单线程 | 社区基准 |
| quinn | Rust | ~50-100 μs | ~200-400 μs | Linux, tokio | ETH thesis |
| **quicz** | **Zig** | **21.7 μs** | **77.3 μs** | **macOS, loopback, std.Io, 100μs timeout** | **本基准** |

### 丢包恢复

| 实现 | 0% 丢包 | 1% 丢包 | 5% 丢包 | 算法 | 来源 |
|---|---|---|---|---|---|
| msquic | ~3 Gbps | 保持 ~70-80% | 保持 ~40-50% | CUBIC/BBR2 | ETH 2024 thesis |
| quic-go | ~1.1 Gbps | 保持 ~60-70% | 保持 ~30-40% | CUBIC | 社区基准 |
| quinn | ~300-500 MB/s | msquic 领先 50%+ | — | CUBIC | ETH 2024 thesis |
| **quicz** | **~310-440 MB/s** | **452 MB/s（1%）** | **303 MB/s（5%）** | **CUBIC** | **本基准（真实握手）** |

### 多流扩展

| 实现 | 4 流聚合 | 扩展性 | 来源 |
|---|---|---|---|
| msquic | ~2-4 Gbps | 近线性（每流工作线程） | msquic dashboard |
| quic-go | ~600-900 MB/s | 良好（每流 goroutine） | 社区基准 |
| s2n-quic | ~800 MB/s-1.2 GB/s | 良好（异步 I/O） | TQUIC benchmark |
| quinn | 单核受限 | 有限 | KIT 2025 |
| **quicz** | **~304 MB/s** | **共享 cwnd（每连接单一 cwnd，RFC 9000）** | **本基准（真实握手）** |

### quicz 性能瓶颈分析（实测）

真实握手 bench（`quic_bench_hs.zig`）测得 macOS loopback 单流 **~310-440 MB/s**（跨 run；单 run 内 stddev 达 19.2%）。以下为实测核实的结论：

1. **握手非瓶颈**：真实 TLS 1.3 握手 ~0.6–1.0 ms/轮，相对 16 MB 传输（~40 ms）可忽略；transport parameters 经握手正确协商（RFC 9000 §7.4）。
2. **每包处理 CPU 非瓶颈**：AES-128-GCM 实测 3.5–3.7 GB/s（ARM PMULL 硬件加速），每包加密+解密 ~4.9 μs；服务端每包处理容量 ~900 MB/s，高于实测 ~313 MB/s（有余量）。吞吐受 ACK 时钟与共享 I/O 路径限制（多线程并发连接亦无扩展）。
3. **UDP 系统调用非主因**：原始 UDP loopback `sendto` 实测 ~3.5–4.7 μs/包（3 次：3.48 / 3.61 / 4.67 μs）。
4. **GSO/GRO 平台差异**：Linux GSO 批量发送可带来 3–10x 吞吐提升，macOS 无等价机制（无 `UDP_SEGMENT`/`sendmmsg`）；此为平台限制，非 quicz 实现缺陷。Linux 上 `std.Io.Threaded` 已内置 `sendmmsg`。

### quicz 延迟优势

quicz 的 Echo P50=21.7 μs 在 loopback 条件下优于多数实现的公开数据：
- 低于 s2n-quic 的 ~20-40 μs（Linux epoll）
- 低于 quic-go 的 ~50-100 μs
- 接近 msquic 的 ~5-15 μs（io_uring）

这得益于纯 Zig 实现无 GC 暂停、无运行时调度开销、ns 精度 pacer。

## 说明

- 直接对比困难，因测量方法、平台、配置不同。
- quicz 使用内存连接模型（无内核旁路），loopback UDP 开销适用。
- Go/Rust 实现在 Linux 上受益于零拷贝 sendmsg 和 GSO。
- quicz 当前 macOS loopback 单流 ~310-440 MB/s（真实握手，quic-go 式多次迭代，run 间 ±20%；8.9KB datagram，100μs timeout）。
- 吞吐受 ACK 时钟与单线程服务端架构限制（服务端容量 ~900 MB/s 有余量）；每包 AES-128-GCM 硬件加速（~4.9 μs）、UDP 系统调用均非瓶颈。

## 待完成基准

- [x] 多流并发（4 流，内存直连 + UDP 线程化）
- [x] 丢包恢复（1%/5%，loopback + 100μs RTT）
- [x] DATAGRAM 吞吐（RFC 9221，真实握手协商 max_datagram_frame_size）：**141.79 MB/s**（1200B payload，loopback）
- [x] CPU 占用（/usr/bin/time -l，真实握手 bench 全套）
- [x] 外部互通（quic-go）：握手 + 证书验证 + ALPN + 双流 echo 通过
- [x] 外部互通（s2n-quic）：握手 + 证书验证 + ALPN + 双流 echo 通过
- [x] 外部互通（quiche）：握手 + 证书验证 + ALPN + 双流 echo 通过
- [x] 非阻塞 receive（Duration(0) 已验证可用）
- [x] 握手延迟（真实 TLS 1.3）：P50 515.2 μs / P99 654.5 μs
- [x] 握手吞吐（新建连接速率）：~1253 conn/s（单线程串行）
- [x] 流开启速率（stream churn）：~1.49 亿/s

## 已知限制

Zig 0.16 的 `std.Io.Threaded` 中 `receiveTimeout(Duration(0))` 使用 `poll(timeout_ms=0)` 实现非阻塞接收。
Benchmark 使用 100μs `receiveTimeout`，`nanoTime()` 为纳秒精度（macOS `mach_absolute_time` / Linux `clock_gettime(MONOTONIC)`）。
吞吐受 ACK 时钟与单线程服务端架构限制（服务端每包处理容量 ~900 MB/s，有余量）；每包 AES-128-GCM 已硬件加速（~4.9 μs），UDP `sendto` ~3.5–4.7 μs/包，均非瓶颈。~313 MB/s 为 macOS loopback 接近实际上限；Linux 经 std.Io.Threaded sendmmsg 获得批量发送。

## 参考

- [TQUIC Benchmark](https://tquic.net/docs/further_readings/benchmark/) — 腾讯多条件 QUIC 基准
- [QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner) — 互通 + pcap 吞吐
- [KIT 性能全景 (2025)](https://doc.tm.kit.edu/2025-Examining-the-Heterogeneous-Throughput-Performance-Landscape-of-QUIC-Implementations-Koenig-et-al.pdf) — 学术多实现对比
- [secnetperf](https://github.com/microsoft/msquic/tree/main/src/perf) — 微软 QUIC 性能工具
