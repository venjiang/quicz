# Backlog

## Zig 0.17.0 迁移

记录日期：2026-10-29。

状态：分支为 `feat/zig-0.17`。先前全部公开运行入口的本地验收通过。
2026-10-30 的补充脚本验收另发现一项缓存参数遗漏，以及一项升级前已有的公共 HTTP/3 失败。
两项问题的状态见下方补充验证记录。
当前根测试及专项回归为 2105/2105，CLI 单元测试为 40/40。
先前全部 97 个运行入口及其扩展、配对场景均通过。握手乱序修复后，跨实现矩阵再次通过 13/13，另有 4 个 Go 扩展场景通过。
握手乱序修复前的 iOS 构建、SDK 链接和模拟器 C ABI 运行均通过。修复后的平台结果须单独核对。
下方首次核验的失败清单仅保留历史证据。
协议源码提交 `668570e4` 的三个远端 CI 作业均通过。实体 iOS 设备仍未运行验收。

迁移前基线：提交 `7beeffa2728b77165be7f99ec3a33a79ec57ab89` 使用 Zig 0.16.0。
本机默认 `zig` 仍为 0.16.0，`zig17` 为 0.17.0。
迁移分支的构建检查、包声明和 `.zigversion` 已改为 0.17.0。

目标：在独立分支中迁移至 Zig 0.17.0，并验证现有行为。
迁移应保持 QUIC wire format、TLS 校验、移动 C ABI 和 socket 所有权不变。
IPv4 P2P 的真实网络故障仍需单独定位，版本升级不构成该故障的修复证据。

### 2026-10-30 补充验证

本轮协议源码为 `668570e4`。此前 97 个公开运行入口均通过，但该结果不覆盖所有公共站点。

- 当前源码重新生成 XCFramework，并通过 iOS 模拟器上的 C ABI 证书校验、流回显和关闭。三项构建及运行检查均通过。
- Linux 到 Mac 的非回环 IPv4 通过静态库构建、C 客户端编译、直连、错误 CA 拒绝和认证打洞五项检查。
  正向和打洞场景各完成 100 轮、6400 字节的逐字节回显，并验证 FIN 和 socket 复用。
- `scripts/h3_longrun.sh` 按原默认参数通过全部 50 轮。每轮均检查四个 HTTP/3 请求结果。
- 公共站点 `cloudflare-quic.com` 返回 HTTP/3 200，并收到 125959 字节。
- `scripts/run_bench_suite.sh` 最初因 Zig 0.17 不接受 `--global-cache-dir` 而退出。
  脚本改用命令级 `ZIG_GLOBAL_CACHE_DIR`，仍使用原固定缓存目录和 `fast` 优化。
  六个基准、执行顺序和失败退出语义不变。旧脚本的回归测试失败，修复后的 macOS 和 Linux 回归均通过。
  修复后使用同一原始命令实际运行六个基准，全部通过，脚本退出码为 0。该结果不构成跨版本性能对比。

### 公共 HTTP/3 握手乱序修复

状态：本地修复和同症状验收已通过。这是升级前已有的问题，不是已证明的 Zig 0.17 回归。
修复提交的 CI 结果单独记录在 PR 中，不沿用旧提交的成功结果。

`www.fastly.com` 的 Handshake 包可能先于包含 ServerHello 的 Initial 包到达。
`Tls13ClientTransport.receive()` 此时调用尚未安装 peer Handshake key 的接收方法。
`Connection.processProtectedHandshakeDatagramWithInstalledKeys()` 返回 `InvalidPacket`，
runtime 将错误发布为握手失败，CLI 请求随即退出。

真实 UDP 记录包含先收到 444 字节 Handshake、后收到 1280 字节 Initial 的失败序列。
按正常顺序接收时，同一公共站点可以返回 HTTP/3 200。
独立 ngtcp2 客户端也对同一地址返回 HTTP/3 200。

离线对照使用同一个合法的受保护 Handshake 包，只改变接收 key 是否已安装。
当前分支与原始 `main@7beeffa2` 分别使用 Zig 0.17 和 0.16，均为已安装 key 的对照通过、提前到达的场景失败。
因此，正常互通通过不能代替乱序握手验收。

修复由 `Tls13ClientTransport` 单独持有最多 32 个提前到达的受保护包。
每个包使用独立副本，长度不超过现有 `max_datagram_size`。队列满时丢弃新包。
密钥就绪后先处理 Handshake，再处理 1-RTT。暂存期间不发送 ACK，也不推进接收 packet number。
有效 Retry、Version Negotiation 重启、transport 关闭、idle 到期和 deinit 均会释放对应副本。
连接仍 active 时，被忽略的 Version Negotiation 保留原队列。Endpoint 的 idle、reset、关闭、close deadline 和 VN 路径统一调用 transport 的失效清理入口。
已接受 VN 的旧 attempt 即使仍 active 也释放队列；新 attempt 携带的协商历史不会误清自己的包。
底层 `Connection` 错误契约、正常握手、认证后的帧错误、TLS 证书拒绝、wire format 和 C ABI 保持原样。

独立回归位于 `src/quic/tls13_client_reordering_tests.zig`，覆盖真实 TLS 的正常与乱序控制、v1/v2、
合并包、1-RTT 顺序、所有权、容量、分配失败、重复包、弃 key、清理，以及认证帧和证书错误。
复审红灯还覆盖忽略 VN、直接恢复 timer，以及真实 endpoint 的 idle、reset、四个 route-bound close、两种 close deadline 和 VN 委派入口。
VN 回归同时检查接受、接受后的路由错误、到期错误，以及新 attempt 的协商历史；原有错误和路由处理顺序不变。
原始离线复现由 1/2 转为 2/2。最终 macOS 根与专项为 2105/2105，CLI 为 40/40。
Linux 原生根与专项为 2103 通过、2 项既有 Darwin-only 跳过。
使用当前源码重建的互通客户端和服务端再次通过 17/17 场景。

同一真实 Fastly 连接被强制先交付 444 字节 Handshake，再交付 1280 字节 Initial，仍返回 HTTP/3 200。
此前原始公共 CLI 脚本完整通过 Cloudflare、Fastly、本地 H3、POST、解析覆盖、HTTPS 和 OpenSSL 七项检查。
后续反复直连还出现了握手等待和请求阶段超时，不能将一次通过表述为公网已完全稳定。
这些结果不代表实体 iOS 或公网、蜂窝 NAT 已验收。

一次并行本地全量检查中，服务端使用原 100ms idle 预算的共享 admission 测试握手失败。
当前版本和 `07d5c90d` 基线的隔离对照均通过。最终以相同用例及原期限串行运行，2104/2104 通过。
没有修改该测试的超时或断言，也没有据此宣称已定位或修复这次偶发失败的根因。

### TLS 未完成时的 ACK 出站

当前 runtime 原先只排空 1-RTT 出站，未将已经处理的 Initial 和 Handshake ACK 发出。
线路回归使用真实客户端和 UDP peer，提供合法 ServerHello 与受保护 Handshake PING，但不完成 TLS。
原代码等待 ACK 时超时。修复后，peer 解密收到的两空间 ACK，并验证对应发送记录被确认。
Initial ACK 还独立解密检查 range 覆盖 server Initial 0，不依赖随后丢弃 Initial 空间的副作用。

客户端现在先排空最多 16 个 long-header 输出，再处理应用出站。
处理复用已有包保护、ACK ranges、空间丢弃和 recovery 逻辑，不延长超时或忽略协议错误。
ACK 修复后的三次 Fastly 直连均完成连接，其中两次 HTTP/3 200，一次在请求阶段超时。
相近验证中的独立 ngtcp2 对同一站点也发生连接超时；这不是该请求超时根因的证明。
请求阶段的偶发超时仍未定位，不应与已复现并修复的缺 key 或 ACK 出站问题混为一谈。

### 公网验收目标替换

2026-10-30 的默认公网验收目标改为 `cloudflare-quic.com` 和 `www.litespeedtech.com`。
两个站点分别通过独立 curl HTTP/3-only 和 Quicz 请求，均返回 HTTP/3 200。
替换后的完整 CLI 脚本通过两项公网检查和五项本地检查，退出码为 0。
公网检查仍使用默认证书校验、25000ms 请求预算、HTTP/3 200 和正文非空断言。
本次未修改协议代码。Fastly 不再作为默认必过目标，但其原有超时记录保留，不能据此宣称故障已修复。

候选站点 `quic.nginx.org` 的独立 curl 请求返回 HTTP/3 200，Quicz 在握手阶段返回 `CryptoError`。
该差异仍待定位，不属于本次替换目标已完成的验证范围，也不能据此认定为 Zig 0.17 回归。
Google 及 LiteSpeed 的 4433 测试端口在独立 curl 和 Quicz 探测中均未通过，未选为默认目标。

### CLI TCP TLS 错误终止

2026-10-30 的 PR 审查发现，CLI 在 TLS 读错误或应用写失败后仍通过 `end()` 发送正常 `close_notify`。
修复在 `TlsStream.read()` 和 `write()` 的错误出口终止输出，并保留原错误。
实现复用已有 `write_closed`，没有新增状态字段、helper、错误告警编码或 QUIC 行为。

- 正常读写保持输出开放，记录分片和密钥序号规则不变。
- 对端正常发送 `close_notify` 时只关闭读侧，本端仍可发送正常关闭通知。
- 记录或 I/O 错误发生后，`end()` 不再写入，后续 `write()` 返回 `StreamClosed`。服务端随后关闭 socket。
- 正常 `end()` 仍只发送一次关闭通知。`end()` 自身写失败后也不会重试。

正式 CLI 回归在修复前为 39/42，修复后为 42/42。
同一真实 TCP 验收从正常请求通过、三类坏记录失败，转为 4/4 通过。
坏记录覆盖损坏认证标签、超限长度和截断输入，均不再被客户端识别为正常 TLS EOF。
应用写入和 flush 失败由内存 Writer 注入，尚未模拟真实 TCP 写失败。完整 CLI 公网及本地脚本为 7/7。
CI 新增 CLI 单元测试步骤。修复提交的 CI 结果单独核对，不沿用旧提交的通过结果。

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
- [x] 解决既有运行失败，使本轮全部示例和本地集成检查通过。
- [x] CI 完整外部互通矩阵通过。
- [x] 同步运行方式和工具链文档，并记录无法执行的验收项。
- [x] `git diff --check` 通过，复审确认改动仅覆盖迁移和已授权的运行失败修复。

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

### 首次完整运行核验

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
用户随后要求继续修复这些失败。当前修复范围和结果见下一节。

### 运行失败修复

本阶段同时处理原始 0.16 基线也存在的失败，不再只修编译器迁移回归。
默认编译器、main 分支、移动 C ABI 和外部项目保持不变。

核心改动如下：

1. CLI TLS 写路径按 16384 字节分片，并在写关闭前发送 `close_notify`。
   读路径处理关闭告警，并拒绝超过 16385 字节的完整 TLSInnerPlaintext。
   上限包含内容类型和 padding，不只限制应用数据。
2. 纯 Zig TLS 客户端在收到 `HANDSHAKE_DONE` 后确认 QUIC 握手。
   服务端保留待发 Handshake CRYPTO，并通过现有 ACK、loss 和 PTO 路径可靠发送确认帧。
3. 旧密钥过期后，不允许接收路径的临时状态副本恢复该密钥。
   未认证包不能只凭 key-phase 位触发连接关闭。
4. Runtime 服务端只交付当前路由连接的实际接收流，不再逐包扫描所有连接的固定流号范围。
   回归覆盖 IPv4、IPv6、高流号、非目标连接隔离和重复 FIN。
5. Runtime 客户端提供可选的 `waitClosed(timeout_ms)`。
   `close()` 仍非阻塞，`deinit()` 仍立即取消任务。
   Closing 阶段按入站计数抑制重复关闭响应，不再用同一关闭帧填满批次。

协议探针已对齐显式时间单位、真实发送记录、握手确认和 key-phase 契约。
Retry TTL 从错误的 10000 纳秒改为明确的 10 秒。
进程服务端在客户端 Finished 后发送握手确认，并忽略上一会话残留的非 Initial 数据报。
P2P 时限测试使用局部受控时钟，不改变生产超时或取消行为。

规模基准与其他性能目标一致，使用 `fast`，保留 500 个客户端及逐字节回显检查。
DebugAllocator 显式启用 `safety=true`，并保留泄漏检查。
这不构成全 Debug 模式下 500 个客户端能在生产默认 idle timeout 内完成的证明。

最终本地验证如下：

- 根测试为 2029/2029，其中库测试为 2008 项，移动 ABI 为 20 项，keepalive 为 1 项。
- Peer punch 为 13/13，runtime metrics 为 27/27。组合构建共执行 2069/2069。
- CLI 为 40/40，覆盖记录分片、合法 padding、超限拒绝、关闭和写失败后的状态。
- 关闭专项为 9/9，覆盖真实受保护数据报、响应抑制、等待超时、取消和 timer 终态发布。
- 全部 97 个入口均通过，无遗漏。主运行清单为 123/123，包含全部八个 event-loop 场景及 H3 配对检查。
- 跨实现证书验证矩阵为 13/13，Go 扩展场景为 4/4。该结果属于本机运行，不代替远端 CI。
- 多连接关闭额外重复三轮，均通过原来的 300 ms 服务器回收断言。
  Retry 并发、轮换及非 Retry 顺序会话均通过。
- 500 客户端规模基准为 500/500，耗时 7.043 秒。逐字节回显和泄漏检查均保留。
- `bench-suite` 的六个程序均实际执行，构建图为 13/13。结果不构成与 0.16 的性能对比。
- CLI 本地集成及 OpenSSL 检查均通过。独立大响应检查收到 49723 字节，与 `Content-Length` 一致。
- 当前源码的 iOS XCFramework 构建和两个 SDK 链接检查已通过。两份头文件与仓库一致。
  iOS 18.6 模拟器通过 C ABI 完成证书校验、回显及关闭。全局 Zig 标准库哈希保持不变。
- CLI 和移动静态库的 Linux x86_64-musl 交叉编译均通过，但本轮没有执行 Linux 运行时验收。
- 修改文件通过格式检查和 diff 检查。两路整分支复审未发现剩余 P1/P2。

最终运行日志和逐项退出码位于上述本机验收目录。
`final-v3-unit-tests.log`、`final-v2-cli-tests.log` 和 `final-v2-results.json` 对应当前验证。
`final-v2-coverage.json` 检查全部运行入口，任一子场景失败都会保留为入口失败。
`final-v2-extra-runtime-results.json`、`final-v2-cross-results.json` 和 `final-v2-ios-results.json` 保存补充结果。
这些报告中的 HEAD 字段是执行开始时的提交，不包含当时的未提交修复。
被测源码在最终复审期间没有变化，`final-v2-source-hashes.txt` 保存其哈希。
本阶段源码最终提交为 `34c8287f`。CLI 修复为 `bc9a21cd`，协议生命周期修复为 `76bb7e77`。
复审以 main 基线至整个任务分支及工作区为范围，不只检查最后一项补丁。

本阶段不改变证书校验、QUIC wire format 或移动 C ABI。
Zig 调用方需要正常完成关闭阶段时，可以显式调用 `close()` 和 `waitClosed()`，再调用 `deinit()`。
默认 `zig` 仍为 0.16.0，本分支使用 `zig17`。
回滚时可回退本阶段的修复提交。完整工具链迁移则按下方方式回到迁移前分支。

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
