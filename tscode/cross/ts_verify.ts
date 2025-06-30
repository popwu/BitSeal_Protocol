// @ts-nocheck
// bun run tscode/cross/ts_verify.ts <jsonFilePath>
import { readFileSync } from 'fs'
import PrivateKey from '../ts-sdk/src/primitives/PrivateKey.js'
import { verifyRequest, buildCanonicalString, bodyHashHex, canonicalQueryString } from '../bitseal/BitSeal.ts'
import { verify as brc77Verify } from '../ts-sdk/src/messages/SignedMessage.js'
import { toArray } from '../ts-sdk/src/primitives/utils.js'
import { sha256 } from '../ts-sdk/src/primitives/Hash.js'

function fixedPrivKey(byteVal: number): PrivateKey {
  return new PrivateKey(Array(31).fill(0).concat([byteVal]))
}

const path = process.argv[2]
if (!path) {
  console.error('usage: bun run ts_verify.ts <json-file>')
  process.exit(1)
}

const data = JSON.parse(readFileSync(path, 'utf8'))
const { method, uriPath, query, body, headers, serverPriv } = data
const serverPrivKey = PrivateKey.fromHex(serverPriv as string)

const ok = verifyRequest(method, uriPath, query, body, headers, serverPrivKey)

// extra direct check
let direct = true
try {
  const sigBytes = toArray(headers['X-BKSA-Sig'], 'base64')
  const canonical = buildCanonicalString(
    method,
    uriPath,
    query,
    body,
    headers['X-BKSA-Timestamp'],
    headers['X-BKSA-Nonce']
  )
  const msgBytes = toArray(canonical, 'utf8')
  direct = brc77Verify(msgBytes, sigBytes, serverPrivKey)
} catch (e) {
  console.error('Direct brc77Verify error', e)
  direct = false
}

console.log('direct verify result', direct)

if (!ok) {
  const canonical = buildCanonicalString(
    method,
    uriPath,
    query,
    body,
    headers['X-BKSA-Timestamp'],
    headers['X-BKSA-Nonce']
  )
  const digestHex = bodyHashHex(canonical)
  console.error('TS verify FAILED')
  console.error('Canonical String:\n' + canonical)
  console.error('Digest(hex):', digestHex)
  console.error('Headers:', headers)
  process.exit(1)
}

console.log('TS verify success') 