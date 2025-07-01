# BitSeal-RTC 未来扩展提案

本文件列出当前实现尚未覆盖、但在后续版本中值得考虑的功能增强。

## 1. KeyUpdate（在线换密钥）
在不中断数据流的情况下轮换会话密钥。
1. 任意一方发送 `KEY_UPDATE { newSalt }` 控制帧；
2. 对端回复 `KEY_UPDATE_ACK { newSalt }`；
3. 双方以旧 `shared_secret` + `newSalt` 再跑一轮 HKDF 得到新 `key_session'`，并将 `seq` 归零；
4. 旧密钥维持短暂重放窗口后销毁。

触发条件示例：
* `seq` 接近 `2^64‐1`；
* 会话持续时间超过 24h；
* 主动提高前向保密。

## 2. ChaCha20-Poly1305 支持
为了更好适配移动端和 WebCrypto 环境，可在 AES-GCM 之外增加 ChaCha20-Poly1305 AEAD 实现，协商方式：
* 握手阶段在 `handshake_msg` 增加 `cipher` 字段，值可为 `aesgcm` 或 `chacha20`。

## 3. BSC3 链式检查点（不可否认性）
定期发送签名的 `checkpoint` 帧：
```
checkpoint = Sign(SK_self, last_seq || SHA256(transcript))
```
离线审计时可证明窗口内所有流量未经篡改。

## 4. 不可靠传输标记
在 `flags` bit0=1 时走 WebRTC `unreliable` 子流，可用于实时语音/视频控制消息。

## 5. 扩充重放窗口
若需维持 `window_size = 128` 或更大，考虑把 bitmap 扩展为两个 `uint64` 或使用 bitset 实现。

## 6. Tag 合并高级档（L+）
实现"仅末片携带 Auth-Tag"，平均节省 ~94 % Tag 开销；
接收端在末片到达前缓存 cipher，末片到达后统一解密验证。

---
以上提案目前尚未排期，欢迎社区反馈与 PR。 