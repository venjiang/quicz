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
- ABI v1提供版本/能力协商，以及阻塞式verified TLS Client生命周期：create、connect、discover、open stream、send、receive、close和destroy。Swift必须在主线程之外执行阻塞调用。
- Swift针对iPhoneOS编译时可以导入C header。
- `connectivity.path_selector`选择首条已验证路径，在更快路径出现时迁移，活动路径失败时降级，并使用RTT迟滞避免抖动切换。
- `connectivity.stun`编码RFC 8489 Binding request，解析transaction匹配的IPv4/IPv6 XOR-MAPPED-ADDRESS success response。
- `connectivity.stun_transaction`在调用方socket上执行最多五次尝试的有界Binding transaction。
- `connectivity.punch_wire`使用短期rendezvous key认证幂等probe/ack，篡改packet在路径路由前被拒绝。
- `connectivity.punch_attempt`要求双向认证流量，拒绝旧attempt和错误nonce，并使用最多五次probe的指数退避。
- `connectivity.punch_driver`在不接管socket所有权的前提下驱动单个remote endpoint打洞状态机。
- `connectivity.candidate`校验有界host/reflexive/relay候选集合，拒绝wildcard和multicast，只生成同地址族pair，使用RFC 8445 pair priority公式并限制pair膨胀。
- `runtime.Client.initWithSocket`接管调用方已绑定的IPv4 UDP socket，保留发现阶段建立的NAT mapping。
- shared-socket loopback证明STUN发现和QUIC stream echo使用同一个客户端UDP端口。
- P2P loopback证明双方先发送认证probe再接收，校验ack后把原socket移交QUIC client/server，验证server证书并在端口不变的情况下完成stream收发。一次macOS loopback样本为双向probe 229微秒、QUIC handshake加echo 29.686毫秒；这只作为回归证据，不代表真实网络性能。
- iOS Simulator中的Swift基准已通过XCFramework C ABI连接真实Host listener，完成证书校验和单条双向stream上的100轮8字节串行回显；一次Debug样本为handshake 53.524毫秒、RTT p50/p95/p99分别为9.863/18.339/23.116毫秒。
- 实体iPhone 14 Pro中的Swift基准已通过同一XCFramework C ABI：先在双方同一UDP socket上完成认证双向probe，再把socket直接用于verified QUIC，完成100轮8字节串行回显、关闭和Host连接状态回收。一次Debug Wi-Fi样本为probe 6.882毫秒、handshake 21.458毫秒、RTT p50/p95/p99分别为13.030/17.551/22.583毫秒。

原iPhoneOS Debug二进制从Swift并发工作线程调用`quicz_mobile_client_create`时，约190 KiB的`Client`值会击穿约512 KiB调用栈并触发SIGBUS。C ABI现在只在构造期间使用短生命周期8 MiB内部线程；同一512 KiB栈回归测试由稳定崩溃转为通过，普通Swift Task真机基准也通过。公开ABI和Client生命周期不变。

构建移动端边界：

```bash
zig build mobile-static \
  -Dtarget=aarch64-ios \
  -Doptimize=ReleaseSafe \
  --prefix /tmp/quicz-ios
```

生成同时包含arm64 iPhoneOS和arm64 Simulator slice的XCFramework：

```bash
scripts/build_mobile_xcframework.sh zig-out/QuiczMobile.xcframework
```

生成的XCFramework包含独立`ios-arm64`和`ios-arm64-simulator` slice，并共享同一公开header。

实体移动端基准的Host先等待带短期key与attempt ID的认证probe，再从首个合法packet学习Device endpoint；
随后在同一socket上执行反向probe并启动QUIC listener：

```bash
zig build run-mobile-latency-server -- 4433 passive-punch
```

wildcard socket的bound endpoint可能返回`0.0.0.0`。平台候选收集必须把bound port与可达接口地址组合，
不得向peer发布wildcard地址。

## 明确尚未实现

- 真实STUN服务与蜂窝网络验证。
- Relay候选交换与真实NAT打洞验证。
- Rendezvous和Relay datagram协议。
- 实体iPhone生命周期与真实蜂窝网络验证。
- 活动应用stream在Relay与Direct路径之间无感迁移。

能力位不得提前声明这些未完成能力。

## 验收顺序

1. 保持完整QUIC回归与UDP path-validation示例通过。
2. 从Swift编译并导入arm64 iOS静态库。
3. 增加一个owned UDP socket，在同一本地端口上先运行STUN，再驱动QUIC；loopback spike已完成。
4. 证明iPhone与Host之间的认证stream echo。已完成。
5. 增加有界Direct探测与即时Relay fallback。同socket Direct探测已完成，Relay并行fallback待完成。
6. 在相同LAN、Wi-Fi、蜂窝、CGNAT、UDP禁用和网络切换矩阵下，与Mons WSS Relay基线比较成功率和延迟。

参考：[RFC 8489](https://www.rfc-editor.org/info/rfc8489/)、
[RFC 8445](https://www.rfc-editor.org/info/rfc8445/)和
[RFC 9000](https://www.rfc-editor.org/info/rfc9000/)。
