# BitSeal-RTC 协议设计草案

> 适用于 WebRTC DataChannel 的轻量级端到端安全层，兼容 BitSeal 思想、无需预注册。

---
## 1. 总览
BitSeal-RTC 将安全逻辑拆为两层：

| 层级 | 名称 | 作用 |
|------|------|------|
| **BSH1** | BitSeal Handshake Layer v1 | 以 ECDSA/Schnorr 互签 + ECDH 派生会话密钥，实现双向身份认证与密钥协商 |
| **BST2** | BitSeal Secure Transport Layer v2 | 基于派生密钥的 AEAD 对称加密传输，利用 64-bit 序列号防重放，支持零交互、低延迟的大报文 |

> 默认数据流走 WebRTC/SCTP 的 `reliable` 模式，底层自动分片与重组。若需部分可靠，可在 Flags 字段扩展。

---
## 2. BSH1：握手层

1. **握手消息格式**（JSON-CBOR 均可）：
   ```json
   {
     "proto": "BitSeal-RTC/1.0",
     "pk": "<33B compressed>",
     "salt": "<4B hex>",
     "ts": 1700000123456,
     "nonce": "128-bit hex"
   }
   ```
2. 双方各自生成 `salt_A / salt_B` 和随机 `nonce`，计算
   ```
   digest = SHA256(canonical(handshake_msg))
   sig    = SignedMessage.sign(digest, SK_self, PK_peer)
   ```
3. 交换 `{handshake_msg, sig}`；验证对方签名后：
   ```
   shared_secret = ECDH(SK_self, PK_peer)
   key_session   = HKDF(shared_secret, salt_A || salt_B)
   salt_session  = salt_A || salt_B      // 4B 发向 → 4B 收向
   seq_init      = random 64-bit         // 各方向独立
   ```
4. 至此进入 **BST2**。

---
## 3. BST2：传输层

### 3.1 Nonce 构造
```
Nonce = salt_session(4B) || seq(8B)
```
* `salt_session` 在握手期确定，单向固定。
* `seq` 为 64-bit 单调递增计数器，首次可随机起跳，**不得回绕**；溢出前必须重新握手换密钥。

### 3.2 AEAD 选型
* 推荐 `ChaCha20-Poly1305`（移动端）或 `AES-256-GCM`（桌面）。
* Auth Tag 均为 16 B。

### 3.3 记录格式
```
+---------+---------+------------+-------------+-----------+
| len(4B) | flags(1)| seq(8B)    | ciphertext  | tag(16B)  |
+---------+---------+------------+-------------+-----------+
```
* **len**：`flags || seq || ciphertext || tag` 的总长度，网络字节序。
* **flags**：bit0=0 表示可靠，1=不可靠；bit1 保留……
* **Associated Data (AD)** = `flags || seq`。
* **ciphertext**：`AEAD_Encrypt(key_session, Nonce, plaintext, AD)` 的输出。

### 3.4 发送流程
```
seq += 1
nonce = salt || seq
cipher, tag = AEAD_Encrypt(key, nonce, plaintext, AD)
frame = len || flags || seq || cipher || tag
DataChannel.send(frame)
```
> **拆包透明**：WebRTC/SCTP 会按 MTU 把 `frame` 分段传输，所有段共享同一 `seq`，接收端重组到完整 `frame` 后再解密。

### 3.5 接收端滑动窗口
```text
window_size = 128     // 可调
max_seq     = -1
bitmap      = 0
```
处理流程：
1. 若 `seq < max_seq - window_size + 1` ⇒ 丢弃（过旧 / 重放）。
2. 若 `seq > max_seq`：窗口右移 `shift = seq - max_seq`，`bitmap <<= shift`，再 `bitmap |= 1`，更新 `max_seq`。
3. 否则落在窗口内：若 `bitmap` 已标 1 ⇒ 丢弃重复；否则置位。
4. 尝试 `AEAD_Decrypt`；失败即丢包。

### 3.6 应用层分片（L 档，最大 64 MiB）

若单条明文 >≈ 60 KiB，SCTP 的 `MaxMessageSize` 及浏览器缓冲都会成为瓶颈。
BST2 规定在记录层之上再做**可选的应用层分片**，默认提供一档 "L" 级配置：

| 参数              | 数值          | 说明 |
|-------------------|--------------|------|
| `FRAG_SIZE`       | 16 KiB       | 每片明文大小，权衡 MTU 与头部开销 |
| `MAX_FRAGS`       | 4 096        | 单报文允许的最大片数 |
| 最大报文尺寸      | 64 MiB       | `FRAG_SIZE × MAX_FRAGS` |

**片头格式（16 B，网络字节序）**
```
+---------+----------+---------+------------+
|flags(1B)|msgID(3B) |fragID(2)|total(2)    |
+---------+----------+---------+------------+
|                seq   (8B)                 |
+---------+-----------------------------------+
```
* `msgID`：24 bit 逻辑报文编号，循环使用；
* `fragID / total`：当前片序号与总片数；
* `seq`：沿用 BST2 64-bit 序列号（即 Nonce 后 8 B）；发送每片都 `seq+=1`；
* `flags.bit0`：末片标记；仅末片携带 16 B Auth-Tag，可省 15/16 ≈ 94 % Tag 开销。

**加解密与重组流程**
1. 发送端按 `FRAG_SIZE` 切片 → 逐片依次 `seq+=1`，独立 AEAD 加密；末片附加 Tag。  
2. 接收端先走 3.5 的 64-bit 重放窗口；解密成功后缓存 `{msgID, fragID}`。  
3. 收到末片并确认 `0…total-1` 片全部到齐 ⇒ 按序拼接得到完整明文。  
4. 对同一 `msgID` 设 60 s 超时，超时未齐则丢弃缓存。

> L 档默认即可覆盖 99% 的文件/图片传输需求；若需更大报文，可将 `FRAG_SIZE` 提升至 32 KiB 或放宽 `MAX_FRAGS`（16 B 片头可支撑至 ≈1 GiB）。

---
## 4. 重键与会话更新
* `seq` ≥ 2⁶⁴-1 或会话持续 >24h ⇒ 触发重新握手（BSH1）。
* 可支持 KeyUpdate 帧：双方协商新 `salt_session` 并重新置 0 序列号。

---
## 5. 可选 BSC3：链式检查点
若需**不可否认性**
1. 每隔 *N* 秒将 `last_seq || SHA256(transcript)` 签名后发送 `checkpoint` 帧。
2. 这样可在离线审计时证明整个窗口流量未被篡改。

---
## 6. 安全注意事项
1. **Nonce 不重用**：`salt+seq` 组合必须唯一；任何方向回绕前强制换密钥。
2. **时间同步**：`ts` 仅用于握手防回放，可宽容 ±300 s。
3. **帧界定**：若使用 DataChannel 的"message"模式，可省 `len` 字段；但"binary stream"模式下必须携带长度。
4. **回放窗口**：`window_size` 越大，内存越多；128 位即可抵御常见网络抖动。

---
## 7. 与现有协议比较
| 协议 | 握手 | 加密 | 重放防护 | 特色 |
|-------|-------|-------|-----------|-------|
| DTLS | X.509 / PSK | AEAD + epoch/seq | 是 | 证书链复杂，4 次 RTT |
| QUIC | TLS 1.3 | AEAD + pkt num | 是 | 0-RTT，面向连接 |
| **BitSeal-RTC** | BSH1 (ECDSA/Schnorr) | AEAD + 64-bit seq | 是 | 无需 CA，P2P 一次 RTT |

---
## 8. 实现参考
* TypeScript: `tscode/ts-sdk/...` 将提供 WebRTC adapter；
* Go: `gocode/go-sdk/...` 计划添加 `rtc` 子包。

> 本文档为初稿，欢迎 Issue / PR 反馈。 