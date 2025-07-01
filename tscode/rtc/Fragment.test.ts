// @ts-nocheck
import { Fragmenter, Reassembler } from './Fragment'
import PrivateKey from '../ts-sdk/src/primitives/PrivateKey.ts'
import { Session } from './BitSealRTC.js'
import { randomBytes } from 'crypto'

function key(byteVal:number): PrivateKey {
  const bytes = new Array(32).fill(0)
  bytes[31] = byteVal
  return new PrivateKey(bytes)
}

test('fragment roundtrip', () => {
  const self = key(1)
  const peer = key(2)

  const saltA = [1,2,3,4]
  const saltB = [5,6,7,8]

  const sessA = Session.create(self, peer.toPublicKey(), saltA, saltB)
  const sessB = Session.create(peer, self.toPublicKey(), saltA, saltB)

  const fragA = new Fragmenter(sessA)
  const recvB = new Reassembler(sessB)

  const msg = Array.from(randomBytes(1<<20))
  const frames = fragA.encode(msg)

  let assembled = null
  for (const f of frames) {
    const res = recvB.push(f)
    if (res.done) {
      assembled = res.msg
      break
    }
  }
  expect(assembled).not.toBeNull()
  expect(Array.from(assembled!)).toStrictEqual(msg)
}) 