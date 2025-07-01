// @ts-nocheck
import { Session } from './BitSealRTC.js'

export const FRAG_SIZE = 16 * 1024 // 16 KiB
export const MAX_FRAGS = 4096      // 64 MiB

// Header: 1(flags) +3(msgID)+2(fragID)+2(total) = 8 bytes
const HDR_LEN = 8

export class Fragmenter {
  private sess: Session
  private nextMsgID = 0

  constructor (sess: Session) {
    this.sess = sess
  }

  encode (plain: number[]|Uint8Array): Uint8Array[] {
    const payload = Array.from(plain)
    const total = Math.ceil(payload.length / FRAG_SIZE)
    if (total > MAX_FRAGS) throw new Error('message too large')
    if (total === 0) return []

    this.nextMsgID = (this.nextMsgID + 1) & 0xFFFFFF
    const msgID = this.nextMsgID

    const frames: Uint8Array[] = []
    for (let i = 0; i < total; i++) {
      const frag = payload.slice(i * FRAG_SIZE, (i + 1) * FRAG_SIZE)
      const flags = (i === total - 1) ? 0x01 : 0x00
      const hdr = buildHeader(flags, msgID, i, total)
      const plaintext = [...hdr, ...frag]
      const frame = this.sess.encode(plaintext, 0)
      frames.push(Uint8Array.from(frame))
    }
    return frames
  }
}

export class Reassembler {
  private sess: Session
  private cache: Map<number, MsgBuf>
  constructor (sess: Session) {
    this.sess = sess
    this.cache = new Map()
  }

  push (frame: Uint8Array): { done: boolean, msg?: Uint8Array } {
    const plain = this.sess.decode(Array.from(frame))
    const flags = plain[0]
    const msgID = read24(plain.slice(1, 4))
    const fragID = (plain[4] << 8) | plain[5]
    const total = (plain[6] << 8) | plain[7]
    const data = plain.slice(HDR_LEN)

    let buf = this.cache.get(msgID)
    if (!buf) {
      buf = { total, frags: new Array(total), received: 0 }
      this.cache.set(msgID, buf)
    }
    if (!buf.frags[fragID]) {
      buf.frags[fragID] = data
      buf.received++
    }
    if ((flags & 1) === 1 && buf.received === buf.total) {
      // assemble
      const joined: number[] = []
      for (let i = 0; i < buf.total; i++) joined.push(...buf.frags[i]!)
      this.cache.delete(msgID)
      return { done: true, msg: Uint8Array.from(joined) }
    }
    return { done: false }
  }
}

type MsgBuf = { total: number, frags: Array<number[]|undefined>, received: number }

function buildHeader (flags: number, msgID: number, fragID: number, total: number): number[] {
  const hdr = new Array(HDR_LEN).fill(0)
  hdr[0] = flags & 0xff
  hdr[1] = (msgID >> 16) & 0xff
  hdr[2] = (msgID >> 8) & 0xff
  hdr[3] = msgID & 0xff
  hdr[4] = (fragID >> 8) & 0xff
  hdr[5] = fragID & 0xff
  hdr[6] = (total >> 8) & 0xff
  hdr[7] = total & 0xff
  return hdr
}

function read24 (b: number[]): number { return (b[0] << 16) | (b[1] << 8) | b[2] } 