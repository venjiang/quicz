# P2P Connectivity Spike

状态：实验性；尚不是可用于生产的NAT穿透API。

## 目标

保持QUIC传输与连接发现分层，同时验证`quicz`可以作为移动P2P应用的数据面。

```text
应用控制面
   |
connectivity：候选、STUN、打洞、Relay fallback
   |
quicz：TLS 1.3、QUIC stream、恢复、迁移、multipath
```

应用身份、Session、授权和payload语义均保留在`quicz`之外。

## 第一检查点已实现

- `mobile-static`生成arm64 iOS静态库并安装`quicz_mobile.h`。
- ABI v1提供版本与已实现传输能力协商。
- Swift针对iPhoneOS编译时可以导入C header。
- `connectivity.path_selector`选择首条已验证路径，在更快路径出现时迁移，活动路径失败时降级，并使用RTT迟滞避免抖动切换。
- `connectivity.stun`编码RFC 8489 Binding request，解析transaction匹配的IPv4/IPv6 XOR-MAPPED-ADDRESS success response。

构建移动端边界：

```bash
zig build mobile-static \
  -Dtarget=aarch64-ios \
  -Doptimize=ReleaseSafe \
  --prefix /tmp/quicz-ios
```

## 明确尚未实现

- STUN transaction定时器与socket驱动。
- ICE候选检查或UDP打洞。
- Rendezvous和Relay datagram协议。
- C ABI中的Endpoint、Connection和Stream句柄。
- iOS生命周期与真实蜂窝网络验证。
- 活动应用stream在Relay与Direct路径之间无感迁移。

能力位不得提前声明这些未完成能力。

## 验收顺序

1. 保持完整QUIC回归与UDP path-validation示例通过。
2. 从Swift编译并导入arm64 iOS静态库。
3. 增加一个owned UDP socket，在同一本地端口上先运行STUN，再驱动QUIC。
4. 证明iPhone与Host之间的认证stream echo。
5. 增加有界Direct探测与即时Relay fallback。
6. 在相同LAN、Wi-Fi、蜂窝、CGNAT、UDP禁用和网络切换矩阵下，与隔离Iroh参照比较成功率和延迟。

参考：[RFC 8489](https://www.rfc-editor.org/info/rfc8489/)、
[RFC 8445](https://www.rfc-editor.org/info/rfc8445/)和
[RFC 9000](https://www.rfc-editor.org/info/rfc9000/)。
