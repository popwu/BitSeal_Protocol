// @ts-nocheck
import fs from 'node:fs'
import { Fragmenter, Reassembler } from '../rtc/Fragment'
import PrivateKey from '../ts-sdk/src/primitives/PrivateKey.ts'
import { Session } from '../rtc/BitSealRTC.js'
import { toHex, toArray } from '../ts-sdk/src/primitives/utils.js'
import { sha256 } from '../ts-sdk/src/primitives/Hash.js'

function key(byteVal: number): PrivateKey {
  const arr = new Array(32).fill(0)
  arr[31] = byteVal
  return new PrivateKey(arr)
}

const inFile = process.argv[2] || 'frames_go.json'
const outFile = process.argv[3] || 'frames_ts.json'

const rawJSON = fs.readFileSync(inFile, 'utf8')
const { digest, frames } = JSON.parse(rawJSON)

const saltA = [1, 2, 3, 4]
const saltB = [5, 6, 7, 8]

const self = key(2) // B side
const peer = key(1)

const sess = Session.create(self, peer.toPublicKey(), saltA, saltB)
const recv = new Reassembler(sess)

let msg: Uint8Array | null = null
for (const hexStr of frames) {
  const buf = Uint8Array.from(toArray(hexStr, 'hex'))
  const res = recv.push(buf)
  if (res.done) {
    msg = res.msg!
  }
}
if (!msg) {
  console.error('[TS] failed to reassemble')
  process.exit(1)
}
const calcDigest = toHex(Array.from(sha256(Array.from(msg))))
if (calcDigest !== digest) {
  console.error('[TS] digest mismatch')
  process.exit(1)
}
console.log('[TS] digest verified')

// re-encode and output frames for Go verify
const frag = new Fragmenter(sess)
const framesOut = frag.encode(Array.from(msg))
const hexFramesOut = framesOut.map(f => toHex(Array.from(f)))
const outObj = { digest, frames: hexFramesOut }
fs.writeFileSync(outFile, JSON.stringify(outObj, null, 2))
console.log('[TS] wrote', outFile) 