// @ts-nocheck
import PrivateKey from '../ts-sdk/src/primitives/PrivateKey.ts'
import PublicKey from '../ts-sdk/src/primitives/PublicKey.ts'
import { sha256 } from '../ts-sdk/src/primitives/Hash.ts'
import { toHex, toArray, toUTF8 } from '../ts-sdk/src/primitives/utils.ts'
import { sign as brc77Sign, verify as brc77Verify } from '../ts-sdk/src/messages/SignedMessage.ts'
import { AESGCM, AESGCMDecrypt } from '../ts-sdk/src/primitives/AESGCM.ts'
import { randomBytes } from 'crypto'

const PROTO = 'BitSeal-RTC/1.0'
const TAG_SIZE = 16

export const buildHandshake = (selfPriv, peerPub) => {
  const salt = Array.from(randomBytes(4))
  const msg = {
    proto: PROTO,
    pk: selfPriv.toPublicKey().encode(true, 'hex'),
    salt: toHex(salt),
    ts: Date.now()
  }
  const raw = toArray(JSON.stringify(msg), 'utf8')
  const sig = brc77Sign(raw, selfPriv, peerPub)
  return { raw, sig, salt }
}

export const verifyHandshake = (raw, sig, selfPriv) => {
  const json = JSON.parse(toUTF8(raw))
  if (json.proto !== PROTO) throw new Error('proto mismatch')
  const peerPub = PublicKey.fromString(json.pk)
  const ok = brc77Verify(raw, sig, selfPriv)
  if (!ok) throw new Error('sig invalid')
  const salt = toArray(json.salt, 'hex')
  return { peerPub, salt }
}

const deriveKey = (shared, saltSelf, saltPeer) => {
  const data = [...shared, ...saltSelf, ...saltPeer]
  return sha256(data)
}

export class Session {
  constructor (key, salt) {
    this.key = key
    this.salt = salt
    this.seq = 0n
    this.windowSize = 128n
    this.maxSeq = 0n
    this.bitmap = 0n
  }

  static create (selfPriv, peerPub, saltSelf, saltPeer) {
    const shared = selfPriv.deriveSharedSecret(peerPub).encode(true)
    const key = deriveKey(shared, saltSelf, saltPeer)
    return new Session(key, saltSelf)
  }

  encode (plaintext, flags = 0) {
    this.seq += 1n
    const seqBytes = bigIntToBytes(this.seq, 8)
    const nonce = [...this.salt, ...seqBytes]
    const ad = [flags, ...seqBytes]
    const { result: cipher, authenticationTag: tag } = AESGCM(plaintext, ad, nonce, this.key)
    const len = 1 + 8 + cipher.length + TAG_SIZE
    return [...u32be(len), flags, ...seqBytes, ...cipher, ...tag]
  }

  decode (frame) {
    if (frame.length < 4 + 1 + 8 + TAG_SIZE) throw new Error('short')
    const len = u32beToInt(frame.slice(0, 4))
    if (len !== frame.length - 4) throw new Error('len mismatch')
    const flags = frame[4]
    const seq = bytesToBigInt(frame.slice(5, 13))
    if (!this.accept(seq)) throw new Error('replay')
    const cipher = frame.slice(13, frame.length - TAG_SIZE)
    const tag = frame.slice(frame.length - TAG_SIZE)
    const seqBytes = frame.slice(5, 13)
    const nonce = [...this.salt, ...seqBytes]
    const ad = [flags, ...seqBytes]
    const plain = AESGCMDecrypt(cipher, ad, nonce, tag, this.key)
    if (plain == null) throw new Error('decrypt fail')
    return plain
  }

  accept (seq) {
    if (seq > this.maxSeq) {
      const shift = seq - this.maxSeq
      if (shift >= this.windowSize) {
        this.bitmap = 0n
      } else {
        this.bitmap <<= shift
      }
      this.bitmap |= 1n
      this.maxSeq = seq
      return true
    }
    const offset = this.maxSeq - seq
    if (offset >= this.windowSize) return false
    if ((this.bitmap >> offset) & 1n) return false
    this.bitmap |= 1n << offset
    return true
  }
}

// helpers
const u32be = (n) => [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]
const u32beToInt = (b) => (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]
const bigIntToBytes = (n, len) => {
  const arr = new Array(len).fill(0)
  for (let i = len - 1; i >= 0; i--) {
    arr[i] = Number(n & 0xffn)
    n >>= 8n
  }
  return arr
}
const bytesToBigInt = (b) => b.reduce((acc, v) => (acc << 8n) + BigInt(v), 0n) 