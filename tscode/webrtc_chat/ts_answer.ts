// @ts-nocheck
import fs from 'node:fs'
import wrtc from '@koush/wrtc'
import { Fragmenter, Reassembler } from '../rtc/Fragment'
import PrivateKey from '../ts-sdk/src/primitives/PrivateKey.ts'
import { Session } from '../rtc/BitSealRTC.js'
import { randomBytes } from 'crypto'
import path from 'node:path'

interface Signal { sdp: string, type: string }

function key (val: number): PrivateKey {
  const a = new Array(32).fill(0)
  a[31] = val
  return new PrivateKey(a)
}

function readOffer (): Signal {
  const data = fs.readFileSync('../offer.json', 'utf8')
  return JSON.parse(data)
}

function writeAnswer (desc: wrtc.RTCSessionDescriptionInit): void {
  const sig: Signal = { sdp: desc.sdp ?? '', type: 'answer' }
  fs.writeFileSync('../answer.json', JSON.stringify(sig))
}

async function main () {
  const pc = new wrtc.RTCPeerConnection({
    iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
  })

  // prepare session
  const self = key(2)
  const peer = key(1)
  const saltA = [1, 2, 3, 4]
  const saltB = [5, 6, 7, 8]
  const sess = Session.create(self, peer.toPublicKey(), saltA, saltB)
  const frag = new Fragmenter(sess)
  const recv = new Reassembler(sess)

  // Read file from CLI
  const filePath = process.argv[2]
  let fileName = ''
  let fileData: Uint8Array = new Uint8Array(0)
  if (filePath) {
    fileName = path.basename(filePath)
    fileData = fs.readFileSync(filePath)
    console.log('[TS] Will send file', fileName, 'bytes', fileData.length)
  }

  pc.ondatachannel = (ev) => {
    const dc = ev.channel
    dc.binaryType = 'arraybuffer'
    dc.onopen = () => {
      console.log('[TS] DataChannel open, sending file…')
      if (fileName) {
        const meta = [1, ...Array.from(Buffer.from(fileName, 'utf8'))]
        const frames1 = frag.encode(meta)
        const dataVec = [2, ...Array.from(fileData)]
        const frames2 = frag.encode(dataVec)
        for (const f of frames1) dc.send(f)
        for (const f of frames2) dc.send(f)
        console.log('[TS] Sent', frames1.length+frames2.length, 'frames')
      }
    }
    dc.onmessage = (e) => {
      const buf = new Uint8Array(e.data as ArrayBuffer)
      const res = recv.push(buf)
      if (res.done) {
        console.log('[TS] Received complete message, bytes:', res.msg!.length)
      }
    }
  }

  let wrote = false;

  function writeOnce() {
    if (!wrote) {
      wrote = true;
      console.log('[TS] Writing answer.json')
      writeAnswer(pc.localDescription!)
    }
  }

  pc.onicecandidate = (ev) => {
    if (ev.candidate) {
      console.log('[TS] ICE cand gathered')
      writeOnce()
    } else {
      console.log('[TS] onicecandidate null')
      writeOnce()
    }
  }

  pc.oniceconnectionstatechange = () => {
    console.log('[TS] ICE conn state:', pc.iceConnectionState)
  }

  pc.onsignalingstatechange = () => {
    console.log('[TS] signaling state:', pc.signalingState)
  }

  const offer = readOffer()
  await pc.setRemoteDescription({ type: 'offer', sdp: offer.sdp })

  const answer = await pc.createAnswer()
  await pc.setLocalDescription(answer)

  pc.onicegatheringstatechange = () => {
    console.log('[TS] Gathering state:', pc.iceGatheringState)
    if (pc.iceGatheringState === 'complete') writeOnce()
  }

  // fallback: if still not written after 3s, write anyway
  setTimeout(writeOnce, 3000)

  // keep process alive until message received
  await new Promise<void>((resolve) => {
    pc.onconnectionstatechange = () => {
      if (pc.connectionState === 'closed' || pc.connectionState === 'failed') resolve()
    }
  })
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
}) 