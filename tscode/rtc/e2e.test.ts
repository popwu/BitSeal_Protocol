// @ts-nocheck
import { Fragmenter, Reassembler } from './Fragment'
import { Session } from './BitSealRTC.js'
import PrivateKey from '../ts-sdk/src/primitives/PrivateKey.ts'
import { randomBytes } from 'crypto'

function priv(byteVal:number):PrivateKey {
  const bytes = new Array(32).fill(0)
  bytes[31] = byteVal
  return new PrivateKey(bytes)
}

describe('BitSeal-RTC e2e', () => {
  test('out-of-order & duplicate reassembly (4MiB)', () => {
    const alice = priv(1)
    const bob = priv(2)
    const saltA = [1,2,3,4]
    const saltB = [5,6,7,8]

    const sessA = Session.create(alice, bob.toPublicKey(), saltA, saltB)
    const sessB = Session.create(bob, alice.toPublicKey(), saltA, saltB)

    const fragA = new Fragmenter(sessA)
    const recvB = new Reassembler(sessB)

    const msg = Array.from(randomBytes(4<<20)) // 4 MiB
    const frames:number[][] = fragA.encode(msg).map(f=>Array.from(f))

    // duplicate 10 random frames (append after originals to keep order relatively intact)
    for(let i=0;i<10;i++){
      const idx = Math.floor(Math.random()*frames.length)
      frames.push(frames[idx])
    }
    // shuffle within windows of 32 to stay within replay window (64)
    const chunk=32
    for(let start=0;start<frames.length;start+=chunk){
      const end=Math.min(start+chunk,frames.length)
      for(let i=start;i<end-1;i++){
        const j = start + Math.floor(Math.random()*(end-start))
        const tmp=frames[i];frames[i]=frames[j];frames[j]=tmp
      }
    }

    let assembled:Uint8Array|null=null
    for(const f of frames){
      try{
        const res=recvB.push(Uint8Array.from(f))
        if(res.done) assembled=res.msg!
      }catch{ /* ignore replay/decrypt fails */ }
    }
    expect(assembled).not.toBeNull()
    expect(Array.from(assembled!)).toStrictEqual(msg)
  })

  test('replay window boundary rejects old seq', () => {
    const key = priv(3)
    const salt=[9,9,9,9]
    const sess = Session.create(key, key.toPublicKey(), salt, salt)

    const frames:Uint8Array[]=[]
    for(let i=0;i<70;i++){
      frames.push(Uint8Array.from(sess.encode([i])))
    }
    // decode first 70 sequentially
    frames.forEach(f=>sess.decode(Array.from(f)))

    // replay earliest frame (seq distance >64)
    expect(()=>sess.decode(Array.from(frames[0]))).toThrow()
  })
}) 