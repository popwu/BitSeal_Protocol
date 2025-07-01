// @ts-nocheck
import fs from 'node:fs'
import { verifyHandshake, Session } from '../rtc/BitSealRTC.js'
import PrivateKey from '../ts-sdk/src/primitives/PrivateKey.js'
import { toArray } from '../ts-sdk/src/primitives/utils.js'

function key(byteVal: number): PrivateKey {
  const bytes = new Array(32).fill(0)
  bytes[31] = byteVal
  return new PrivateKey(bytes)
}

if (process.argv.length < 3) {
  console.error('usage: ts_rtc_verify <jsonfile>')
  process.exit(1)
}
const data = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'))

const raw = toArray(data.handshake_raw, 'hex')
const sig = toArray(data.handshake_sig, 'hex')
const saltPeer = toArray(data.salt, 'hex')

const self = key(4)
const peer = key(3)

const { peerPub, salt } = verifyHandshake(raw, sig, self)

const session = Session.create(self, peerPub, salt, saltPeer)

console.log('TS verify OK ✅') 