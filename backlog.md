# Backlog

## Zig 0.17.0 迁移

记录日期：2026-10-29。

状态：迁移进行中。分支为 `feat/zig-0.17`。macOS 原生构建和测试通过，iOS 交叉编译仍受阻。

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
- [ ] 受影响的平台交叉编译和现有外部互通检查通过。
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

iOS 仍是阻塞项。设备和模拟器的 `mobile-static` 构建均在
Zig 0.17.0 的 `std/Io/Threaded.zig` 中失败，错误为 `NullFile` 没有 `fd`。

不依赖 quicz 的最小程序也复现该错误。失败链路为 I/O vtable 的
`processReplace`、`spawnDarwin` 和 `getDevNullFd`。
同一原始 0.16.0 基线的 iOS 静态库编译通过。
本轮没有修改全局标准库，也没有通过切换 I/O 后端绕过失败。
在 iOS 构建恢复前，不应将整个迁移标为完成或合入默认分支。

Retry 进程场景另有 `TokenExpired` 失败。
同一场景在原始 0.16.0 提交上也失败，因此本轮将其记录为既有问题。
本轮未扩大范围修复该问题，也未重新运行完整跨实现互通矩阵。

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
