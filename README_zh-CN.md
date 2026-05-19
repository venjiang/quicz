# quicz

[English](README.md) | 简体中文

`quicz` 是一个使用 [Zig](https://ziglang.org/) 实现的 QUIC 协议栈，目标对齐 IETF QUIC 标准，规范文档见 <https://quicwg.org/>。

> 状态：**实验性 / 开发中（WIP）**  
> 目标：从一个最小但语义正确的子集开始，逐步实现一个完整的 QUIC 传输协议（覆盖 RFC 9000 系列以及 QUIC v2 RFC 9369）。

## 特性与路线图（Features and Roadmap）

### 已实现 / 正在进行

- [x] 项目骨架：Zig 构建集成 + 内存态示例 echo client/server
- [x] `QuicConnection` 的基础 API 设计（初版）
- [x] QUIC 变长整数（varint）编解码工具
- [x] 最小 QUIC 包头（long/short）解析与序列化
- [x] 基础帧模型（STREAM / CRYPTO / PADDING / PING / ACK / CONNECTION_CLOSE 子集）
- [x] 最小内存态连接与 stream 发送队列 / 接收缓存流转
- [x] 简化丢包恢复与拥塞控制状态骨架
- [ ] 完整连接状态机、packet number spaces 与 stream 流量控制
- [ ] 完整 RFC 9002 丢包检测与拥塞控制（含 packet tracking）
- [ ] TLS 1.3 集成（RFC 9001）
- [ ] QUIC v2（RFC 9369）版本支持

### 规划的里程碑

1. **最小 QUIC v1 子集**
   - 单路径、仅 IPv4
   - 固定 QUIC v1 版本（0x00000001）
   - 支持 Initial / Handshake / 1-RTT 包
   - 支持基础 STREAM / ACK / PADDING / CONNECTION_CLOSE 帧
2. **TLS 1.3 + 完整握手**
   - 正式的 CRYPTO 帧
   - 密钥派生与包加密保护
3. **丢包检测与拥塞控制**
   - 基于 RFC 9002 的算法（初期会采用类似 NewReno 的实现）
4. **QUIC v2 与高级特性**
   - QUIC v2 版本（0x6b3343cf）支持
   - 路径迁移、PATH_CHALLENGE / PATH_RESPONSE、stateless reset 等

更详细的设计与每个功能的业务逻辑说明，请参考：

- 英文文档：[`docs/en/`](docs/en/) 目录
- 中文文档：[`docs/zh-CN/`](docs/zh-CN/) 目录

## 构建（Build）

需要安装 Zig 稳定版本（当前开发与测试使用 **0.16.0**）。

```bash
zig build
```

上述命令会构建：

- 静态库：`libquicz.a`
- 示例程序：
  - `zig-out/bin/quicz-echo-server`
  - `zig-out/bin/quicz-echo-client`

## 作为库使用（Using quicz as a library）

高层 API（仍可能演进）：

```zig
const std = @import("std");
const quicz = @import("quicz");

pub fn main() !void {
    const gpa = std.heap.page_allocator;

    var conn = try quicz.QuicConnection.init(
        gpa,
        .client,
        .{
            .max_datagram_size = 1350,
            .initial_rtt_ms = 333,
        },
    );
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "hello, quicz"[0..], true);

    // 当前骨架行为：
    // - 调用 conn.pollTx(...) 获取未加密的 frame payload 字节
    // - 将对端 payload 字节喂给 conn.processDatagram(...)
    // - 通过 conn.recvOnStream(...) 读取应用层数据
    // 完整 UDP packetization、TLS 与 packet protection 仍未实现。
}
```

更多示例用法，请参考：

- [`examples/echo_server.zig`](examples/echo_server.zig)
- [`examples/echo_client.zig`](examples/echo_client.zig)

这些示例当前用于演示内存态 frame-payload API，并不是可互通的 QUIC-over-UDP 程序。

## 文档结构（Documentation Layout）

项目文档使用中英文目录区分存放：

- 英文文档：`docs/en/`
  - 作为权威、完整的设计与业务逻辑说明
  - 当前已有：`docs/en/spec.md`
- 中文文档：`docs/zh-CN/`
  - 对应英文文档的等价翻译与本地化说明
  - 当前已有：`docs/zh-CN/spec.md`

代码中的标识符与注释统一使用英文；中文文档主要用于帮助理解与说明，不会影响 API 设计。

## License

MIT
