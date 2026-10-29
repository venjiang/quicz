# Backlog

## Zig 0.17.0 迁移

记录日期：2026-10-29。

状态：review 修复已通过复审。分支为 `feat/zig-0.17`。
完整运行核验已结束，但测试和示例没有全部通过。
本地跨实现矩阵为 13/13，另有 4 个扩展场景通过。远端 CI 仍未验收。
iOS 设备、模拟器静态库构建均通过，模拟器 C ABI 运行也通过。实体设备尚未运行。

迁移前基线：提交 `7beeffa2728b77165be7f99ec3a33a79ec57ab89` 使用 Zig 0.16.0。
本机默认 `zig` 仍为 0.16.0，`zig17` 为 0.17.0。
迁移分支的构建检查、包声明和 `.zigversion` 已改为 0.17.0。

目标：在独立分支中迁移至 Zig 0.17.0，并验证现有行为。
迁移应保持 QUIC wire format、TLS 校验、移动 C ABI 和 socket 所有权不变。
IPv4 P2P 的真实网络故障仍需单独定位，版本升级不构成该故障的修复证据。

### 迁移范围

1. 统一更新编译器版本检查、包声明、CI 和构建脚本中的版本要求。
2. 适配构建系统。将运行步骤的 `b.args` 用法改为 `addPassthruArgs()`。
   检查配置阶段的文件读取、程序查找和环境依赖是否符合新的缓存规则。
3. 适配 C 翻译。0.17.0 移除了 `@cImport`，并弃用了内置 `TranslateC` 步骤。
   现有 `b.addTranslateC` 用法应迁移至官方独立 `translate-c` 包。
   Zig 侧可以继续通过名为 `c` 的模块导入翻译结果。
4. 将已移除的数组乘法 `a ** b` 改为 `@splat`。
5. 将已弃用的 `@intFromEnum`、`@enumFromInt` 迁移至 `@backingInt`、`@fromBackingInt`。
   可以在迁移分支使用 0.17.0 的 `zig fmt` 自动处理这项转换。
6. 检查标准库接口变化。重点包括 `OptimizeMode` 改为 `Optimize`，以及优化模式标签
   `.debug`、`.safe`、`.fast`、`.small`。同时检查 allocator、`ArrayList` 和格式化分配接口。
7. 检查语义变化。`@hasDecl` 在 0.17.0 中只识别公开声明。
   若迁移时出现 `@bitCast` 用法，应检查新的数组和向量语义，以及 `extern` 类型限制。
   若出现带错误捕获的 `errdefer`，应按已移除语法处理。

2026-10-29 的文本扫描发现：数组乘法命中 729 次，旧枚举转换命中 641 次，
`b.args` 命中 64 次，旧优化模式名称命中 31 次，`addTranslateC` 命中 5 次。
扫描范围为 `build.zig`、`src/` 和 `examples/` 中的 Zig 文件。
这些数字不是编译错误数，开始迁移时应重新核对。
本次扫描未发现 `@cImport`、`@bitCast` 或带错误捕获的 `errdefer`。

### 验收标准

- [x] Zig 0.17.0 的版本声明与实际构建工具链一致。
- [x] 修改文件通过 `zig fmt --check` 和适用的 `zig ast-check`。
- [x] `zig build test --summary all` 通过。
- [x] `zig build --summary all` 通过。
- [x] IPv4、IPv6、P2P 和共享 socket 的相关回归通过。
- [x] 移动 C ABI 的本机测试通过，包括超时、取消和 socket 交接。
- [x] 受影响的平台交叉编译通过。
- [x] 核验全部 97 个 `run-*` 入口对应的程序，并与原始基线对照失败项。
- [ ] 解决既有运行失败，使所有示例和集成检查通过。
- [ ] CI 完整外部互通矩阵通过。
- [x] 同步运行方式和工具链文档，并记录无法执行的验收项。
- [x] `git diff --check` 通过，复审确认没有混入协议或功能改动。

### 2026-10-29 验证记录

以下命令中的 `zig17` 均为 Zig 0.17.0。

- 原始 0.16.0 基线与迁移后的完整测试均为 2021/2021。
- `zig17 build --summary all -j4` 通过 205/205 构建步骤。
- CLI 单元测试通过 33/33。原生 CLI 构建和 Linux x86_64-musl 的 `fast` 交叉编译均通过。
- IPv4 P2P 的 100 轮回显、共享 socket、移动 IPv4/IPv6 ABI、移动 deadline 和取消回归均通过。
- C TLS adapter、HTTP/3 runtime 和双连接进程回显均通过。
- 独立 Go 实现与迁移后的客户端、服务端均完成证书验证及双流回显。
- CLI 的本地 HTTPS 和 HTTP/3 证书验证请求均通过。

iOS 最初在 Zig 0.17.0 的 `std/Io/Threaded.zig` 中失败，错误为 `NullFile` 没有 `fd`。
不依赖 quicz 的最小程序也复现该错误，原始 0.16.0 基线则可编译。
问题是 `processReplace` 在不能 spawn 的 iOS 上进入 `spawnDarwin`，最终访问 `getDevNullFd`。

修复仅用于 iOS `mobile-static` 编译。构建会在缓存中复制标准库，
将上述条件改为 `is_darwin and process.can_spawn`。iOS 保留原有 POSIX replacement 路径。

构建使用标准 `sed` 工具和公开的 Zig build API。
缓存副本约为 228 MiB。全局标准库、`Threaded` 后端及 C ABI 均不改变。

设备和模拟器构建各为 6/6，现有脚本的 XCFramework 打包也通过。
两份 C ABI 头文件与仓库一致，两个平台的 SDK 链接检查均通过。尚未在实体设备运行。
CI 已增加两个 iOS 目标的编译门禁。后续上游工具链通过这些门禁后，应移除此兼容步骤。

两个 P2 也已修复。Linux 容器名称现在包含 Zig 版本，旧容器会保留。
benchmark 的元数据查询和构建使用同一个 `${ZIG:-zig}`。
新增 shell 回归先复现两项失败，修复后全部通过。测试模拟容器和编译器，不运行真实性能测试。
修复后的两路复审覆盖原始基线至当前工作区，均未发现剩余或新增 P1/P2。

Retry 进程场景另有 `TokenExpired` 失败。
同一场景在原始 0.16.0 提交上也失败，因此本轮将其记录为既有问题。
迁移和 review 修复阶段没有扩大范围修复该问题。
后续完整运行结果见下一节。

### 完整运行核验

核验日期为 2026-10-29。被测源码提交为 `5f02c0c0`，原始基线为 `7beeffa2`。
迁移分支使用 `zig17` 0.17.0，原始基线使用默认 `zig` 0.16.0。
基线源码从原始提交提取到临时目录，不修改 main 工作区。

本轮结果如下：

- 根测试使用独立缓存实际执行 2021/2021，全部通过。库测试占 2000 项，移动 ABI 占 20 项，runtime keepalive 占 1 项。
- CLI 使用独立缓存实际执行 33/33，全部通过。
- runtime metrics 实际执行 27/27，peer punch 实际执行 13/13，全部通过。专项 mobile ABI 复用本轮根测试的有效结果。
- 构建帮助列出的 97 个 `run-*` 入口对应程序均已核验。默认或配对调用中，85 个通过，12 个失败。
- 需要常驻服务端的程序使用独立端口配对运行。部分配对直接调用同一构建图安装的二进制，不以服务端仅启动作为通过证据。
- `bench-suite` 实际运行六个基准程序并通过。结果只证明可运行，不构成与 0.16 的性能对比。
- QUIC 跨实现矩阵为 13/13。正向覆盖 quic-go、quiche、s2n-quic 的三个场景，反向覆盖 quic-go、quiche、s2n-quic、quinn。
- 该矩阵使用 CA 签发的叶证书，保留证书及主机名校验。Go 的 multiconnect、keyupdate、v2、chacha20 现有场景另为 4/4。
- H3 双向请求、cookie 和重定向配对检查通过。自签名 H3 演示使用其既有跳过校验方式，不归入上述证书验证矩阵。
- iOS 18.6 模拟器通过公开 C ABI 完成 CA 校验、连接、流回显和关闭。该结果不能代替实体设备验收。
- 工具链脚本回归通过。默认编译器和全局标准库保持不变。

下面 12 个入口在 0.17 和原始 0.16 基线均失败。
两版本出现相同错误或失败断言。这些证据表明问题已存在，不能据此推定根因，也不能排除其他性能差异。

| 入口 | 两版本的失败证据 |
| --- | --- |
| `run-transport-parameters` | `TransportParameterExampleFailed`。服务端 stateless reset token 的非空断言失败。 |
| `run-loss-recovery` | `LossRecoveryExampleFailed`。拥塞窗口增长断言失败。 |
| `run-pto-recovery` | `PtoRecoveryExampleFailed`。anti-amplification 下的过期 timer 处理断言失败。 |
| `run-path-validation` | `UnexpectedState`。pending path challenge 计数断言失败。 |
| `run-multi-conn-test` | `ConnectionLeak`。回显结束后的回收窗口仍有存活连接。 |
| `run-tls-openssl-backend-adapter` | `InvalidPacket`。示例再次驱动已丢弃的 Handshake space。 |
| `run-tls-openssl-pair-transcript` | `UnexpectedState`。`recoveryTimerCount() == 0` 断言失败。 |
| `run-udp-endpoint-loopback` | `UnexpectedState`。示例没有取得预期的 poll 结果。 |
| `run-udp-handshake-keys-loopback` | `UnexpectedState`。`recoveryTimerCount() == 0` 断言失败。 |
| `run-udp-crypto-stream-loopback` | `UnexpectedState`。`recoveryTimerCount() == 0` 断言失败。 |
| `run-udp-key-update-loopback` | `UnexpectedState`。ACK key phase 断言失败。 |
| `run-scale-bench` | `ScaleFailed`。默认 500 个客户端中，0.17 成功 97 个，0.16 成功 114 个。 |

以下问题不计入上述 12 个默认入口失败，但仍需处理：

1. `run-interop-event-loopback` 的默认场景通过，额外的 `persistent` 场景在两版本均超时。
2. `scripts/cli_h3_live_test.sh --skip-live` 在两版本均未通过 OpenSSL 检查。
   前四项 H3、POST、resolve 和 HTTPS 检查通过。独立捕获显示 HTTP 200 后出现 `unexpected eof while reading`，OpenSSL 退出码为 1。
3. CLI 的 TCP TLS 路径在发送超过记录缓冲容量的大响应时，会在 `cli/src/tls_tcp.zig:109` 越界并中止进程。
   大目录列表在两版本均复现。该问题属于既有 CLI 服务端缺陷，不是 QUIC transport 的升级修复。
4. 前述 Retry 进程场景的 `TokenExpired` 仍未修复。

本轮没有修改核心协议代码，也没有削弱断言或跳过失败测试。
不能将本次核验表述为“所有测试及示例都通过”。

复查时可以使用以下命令。`RUN` 应指向新的验收目录。

```sh
zig17 build test --cache-dir "$RUN/root-cache" --test-timeout 30s --summary all -j2
(cd cli && zig17 build test --cache-dir "$RUN/cli-cache" --test-timeout 30s --summary all -j2)
zig17 build test-runtime-metrics test-peer-punch test-mobile-abi --summary all -j1
zig17 build bench-suite --summary all -j1
ZIG=zig17 bash scripts/cli_h3_live_test.sh --skip-live
bash scripts/test_zig_toolchain_scripts.sh
```

每个失败入口都可以用 `zig17 build <入口>` 复查。
persistent 场景使用 `zig17 build run-interop-event-loopback -- persistent`。
原始 0.16 基线需要在独立目录使用原始源码构建，不应直接在迁移分支切换编译器。

本机日志、逐项退出码、配对参数和基线结果保存在
`/private/tmp/quicz-zig017-validation.U8HGZg`。
其中 `run-targets-results.json` 汇总入口覆盖，`matrix-results.json` 汇总 17 项互通结果。
`baseline-*-results.json` 保存基线对照。临时目录含测试私钥，不提交到仓库。
这些本机文件可能被系统清理，仓库保留本节的源码版本、命令和失败清单。

尚未完成的验收包括远端 CI 矩阵和实体 iOS 设备运行。
Linux 运行时、本地回环之外的 IPv4 P2P 连通性，以及所有参数组合不在本轮运行证明范围内。
后续应单独安排既有失败修复。优先处理 CLI 大响应中止、连接回收、规模连接和 persistent 超时。

### 收益与风险

0.17.0 的主要预期收益是构建配置缓存和编译工具链改进。
LLVM 从 21 升级至 22.1.8，但循环向量化仍保持关闭。
官方增量编译说明重点覆盖 `x86_64-linux`，不能直接据此承诺 Apple Silicon 的相同收益。
迁移后的构建速度和运行性能需要与同机、同配置的 0.16.0 基线比较。

回滚方式：保留 0.16.0 工具链及迁移前提交。
若迁移尚未满足验收标准，继续使用原有分支和 0.16.0 构建。

### 官方资料

- [Zig 0.17.0 发布说明](https://ziglang.org/download/0.17.0/release-notes.html)。
- [Zig 下载与版本信息](https://ziglang.org/download/)。
- [官方 translate-c 包](https://codeberg.org/ziglang/translate-c)。
