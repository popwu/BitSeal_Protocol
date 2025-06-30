// @ts-nocheck
// BitSeal protocol TypeScript helper

import { sha256 } from '../ts-sdk/src/primitives/Hash.js'
import { toHex, toBase64, toArray } from '../ts-sdk/src/primitives/utils.js'
import PrivateKey from '../ts-sdk/src/primitives/PrivateKey.js'
import PublicKey from '../ts-sdk/src/primitives/PublicKey.js'
import { sign as brc77Sign, verify as brc77Verify } from '../ts-sdk/src/messages/SignedMessage.js'
import { randomBytes } from 'crypto'

export interface BitSealHeaders {
  'X-BKSA-Protocol': 'BitSeal'
  'X-BKSA-Sig': string
  'X-BKSA-Timestamp': string
  'X-BKSA-Nonce': string
  [k: string]: string
}

export const randomNonce = (): string => randomBytes(16).toString('hex')

export function canonicalQueryString (query: string = ''): string {
  if (!query) return ''
  if (query.startsWith('?')) query = query.slice(1)
  const params = new URLSearchParams(query)
  const tuples: Array<[string, string]> = []
  params.forEach((v, k) => tuples.push([k, v]))
  tuples.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
  return tuples.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&')
}

export function bodyHashHex (body: string | undefined | null): string {
  if (!body) return ''
  return toHex(sha256(body, 'utf8'))
}

export function buildCanonicalString (
  method: string,
  uriPath: string,
  query: string,
  body: string,
  timestamp: string,
  nonce: string
): string {
  return [
    method.toUpperCase(),
    uriPath,
    canonicalQueryString(query),
    bodyHashHex(body),
    timestamp,
    nonce
  ].join('\n')
}

export function signRequest (
  method: string,
  uriPath: string,
  query: string,
  body: string,
  clientPriv: PrivateKey,
  serverPub: PublicKey,
  opts: Partial<{ timestamp: string, nonce: string }> = {}
): BitSealHeaders {
  const timestamp = opts.timestamp ?? Date.now().toString()
  const nonce = opts.nonce ?? randomNonce()
  const canonical = buildCanonicalString(method, uriPath, query, body, timestamp, nonce)
  const msgBytes = toArray(canonical, 'utf8')
  const sigBytes = brc77Sign(msgBytes, clientPriv, serverPub)
  const sigBase64 = toBase64(sigBytes)
  return {
    'X-BKSA-Protocol': 'BitSeal',
    'X-BKSA-Sig': sigBase64,
    'X-BKSA-Timestamp': timestamp,
    'X-BKSA-Nonce': nonce
  }
}

export function verifyRequest (
  method: string,
  uriPath: string,
  query: string,
  body: string,
  headers: Record<string, string>,
  serverPriv: PrivateKey
): boolean {
  if (headers['X-BKSA-Protocol'] !== 'BitSeal') return false
  const timestamp = headers['X-BKSA-Timestamp']
  const nonce = headers['X-BKSA-Nonce']
  const sigBase64 = headers['X-BKSA-Sig']
  if (!timestamp || !nonce || !sigBase64) return false
  const canonical = buildCanonicalString(method, uriPath, query, body, timestamp, nonce)
  const msgBytes = toArray(canonical, 'utf8')
  const sigBytes = toArray(sigBase64, 'base64')
  try {
    return brc77Verify(msgBytes, sigBytes, serverPriv)
  } catch {
    return false
  }
} 