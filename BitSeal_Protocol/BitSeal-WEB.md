# BitSeal Protocol Specification

> A registration-free protocol for signing HTTP requests/responses with Bitcoin private keys

## 1. Overview
BitSeal is a lightweight security signature protocol designed for RESTful APIs that requires **no prior registration** to achieve identity authentication, request integrity verification, and replay resistance. The protocol relies on the [BRC-77] message signature format while adding timestamps, nonces, and canonicalization rules at the network layer to ensure end-to-end security even over standard HTTPS channels.

* Header identifier: `X-BKSA-Protocol: BitSeal`
* Roles: a Client holding a Bitcoin private key and a single Server
* Curve: secp256k1
* Hash: SHA-256

---
## 2. Terminology
| Abbr. | Description |
|-------|-------------|
| **SK** | PrivateKey |
| **PK** | PublicKey (compressed, 33 bytes) |
| **Addr** | Bitcoin address derived from PK |
| **Sig** | Signature string in BRC-77 format |
| **Digest** | Result of SHA-256 on the canonical request string |

---
## 3. Roles & Keys
1. **Client**
   * Long-term private key `SK_C` (never transmitted)
   * Public key `PK_C` automatically embedded in `Sig`
2. **Server**
   * Long-term private key `SK_S`
   * Public key `PK_S` published (Docs, DNS TXT, GitHub release, etc.)

> It is recommended that the Client sets `PK_S` as the "recipient public key" during signing so that the signature can only be verified by the Server, thereby improving anti-phishing capability.

---
## 4. Header Fields
| Header | Required | Purpose |
|--------|----------|---------|
| `X-BKSA-Protocol` | yes | Fixed value `BitSeal` |
| `X-BKSA-Sig`      | yes | BRC-77 signature encoded in Base64 |
| `X-BKSA-Timestamp`| yes | Unix timestamp in milliseconds |
| `X-BKSA-Nonce`    | yes | 128-bit random hex, single use |

Business parameters should be placed in the URL query or JSON body.

---
## 5. Canonical Request String
```
METHOD\n
URI_PATH\n
CanonicalQueryString\n
SHA256(body)\n
X-BKSA-Timestamp\n
X-BKSA-Nonce
```
1. **METHOD**: Uppercase `GET`/`POST`…
2. **URI_PATH**: Path only, without hostname or query
3. **CanonicalQueryString**: Sort `key=value` pairs in ASCII order, RFC3986-encode, join with `&`; empty string if no query
4. **SHA256(body)**: Hex (64 chars) SHA-256 of the raw request body; empty string if no body
5. **Timestamp / Nonce**: Same values as headers

Join the six lines with `\n`, then apply SHA-256 again to obtain the **Digest**.

---
## 6. Request Signing
1. Client generates `Timestamp` and `Nonce`, constructs the canonical string → `Digest`
2. Call `SignedMessage.sign(Digest, SK_C, PK_S)` to obtain `Sig`
3. Fill headers and payload, then send via HTTPS

---
## 7. Server Verification
1. Check `Timestamp` within ±ΔT (recommended 300 s)
2. Verify that the `Nonce` has not been used
3. Recompute the canonical string → `Digest`
4. Call `SignedMessage.verify(Digest, Sig, SK_S)`
5. Extract `PK_C` from `Sig` → Address → account / quota checks
6. Process business logic and generate response

---
## 8. Response Signature
The server signs the response body using the same procedure but replaces the first line (`METHOD`) with the HTTP status code and appends the original request `Nonce` as the seventh line, providing symmetric protection.

Example headers:
```
X-BKSA-Protocol: BitSeal
X-BKSA-Sig: <base64>
X-BKSA-Timestamp: 1700000123478
X-BKSA-Nonce: c4b7e6d9408f49f6a22ca1c3
```

---
## 9. Frictionless Account Model
* The server creates an account dynamically with `Addr` as the primary key
* The default daily quota is very low (e.g., 0.01 BTC)
* If the quota is exceeded, return `402` + `B010` to prompt KYC for an increased limit
* The client can send `/key/revoke` to deactivate a key

---
## 10. Error Codes
| HTTP | Code | Meaning |
|------|------|---------|
| 400 | B001 | Missing / malformed headers |
| 401 | B002 | Signature verification failed |
| 401 | B003 | Invalid timestamp / nonce |
| 402 | B010 | Anonymous quota exceeded, KYC required |
| 403 | B011 | Address revoked |
| 403 | B012 | Address banned |
| 500 | B099 | Internal server error |

---
## 11. Security Notes
1. **Replay protection**: Timestamp + Nonce (Bloom filter + LRU)
2. **Privacy**: One-time sub-keys make cross-correlation difficult
3. **TLS**: Still enforce HTTPS + HSTS to prevent downgrade attacks
4. **Private-key safety**: Use hardware wallets or MPC and follow RFC 6979 deterministic `k`
5. **Signature uniqueness**: Employ low-s normalization for ECDSA; the Schnorr upgrade guarantees uniqueness

---
## 12. Reference Implementations
* TypeScript: `tscode/ts-sdk/src/messages/SignedMessage.ts`
* Go: `gocode/go-sdk/message/signed.go`

The SDK wraps signing / verification, canonical string generation, and time synchronization.

---
## 13. Roadmap
| Codename | Change | Notes |
|----------|--------|-------|
| BitSeal-Plus | Switch to Schnorr (BIP-340) | Drop-in replacement; only signature parsing changes |
| BitSeal-MPC | Client adopts threshold signatures / social recovery | Multi-party key shards prevent loss |

---
## 14. Example
```
POST /v1/wallet/withdraw?token=USDT HTTP/1.1
Host: api.example.com
X-BKSA-Protocol: BitSeal
X-BKSA-Timestamp: 1700000123456
X-BKSA-Nonce: c4b7e6d9408f49f6a22ca1c3
X-BKSA-Sig: AjRCSzEB...
Content-Type: application/json

{"amount":0.5,"to":"bc1q..."}
```

Server checks and responds:
```
HTTP/1.1 200 OK
Content-Type: application/json
X-BKSA-Protocol: BitSeal
X-BKSA-Timestamp: 1700000123478
X-BKSA-Nonce: c4b7e6d9408f49f6a22ca1c3
X-BKSA-Sig: BBF0F9...

{"txid":"cc5ef2...","status":"broadcast"}
```
