// @ts-nocheck
// bun run tscode/cross/ts_sign.ts <output.json>
import { writeFileSync } from 'fs'
import PrivateKey from '../ts-sdk/src/primitives/PrivateKey.js'
import { signRequest } from '../bitseal/BitSeal.ts'

function fixedPrivKey(byteVal: number): PrivateKey {
  return new PrivateKey(Array(31).fill(0).concat([byteVal]))
}

const outPath = process.argv[2] || 'ts_sign.json'

const method = 'POST'
const uriPath = '/test'
const query = ''
const body = '{"hello":"world"}'

const clientPriv = fixedPrivKey(3)
const serverPriv = fixedPrivKey(4)

const headers = signRequest(method, uriPath, query, body, clientPriv, serverPriv.toPublicKey())

const obj = { method, uriPath, query, body, headers, serverPriv: serverPriv.toHex() }
writeFileSync(outPath, JSON.stringify(obj))
console.log('TS signed and wrote', outPath) 