// 纯 JS 版本，直接 `node ts_answer.mjs`
import fs from 'node:fs'
import wrtc from '@koush/wrtc'

function readOffer() {
  const data = fs.readFileSync('offer.json', 'utf8')
  return JSON.parse(data)
}

function writeAnswer(desc) {
  const sig = { sdp: desc.sdp ?? '', type: 'answer' }
  fs.writeFileSync('answer.json', JSON.stringify(sig))
}

async function main() {
  const pc = new wrtc.RTCPeerConnection({
    iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
  })

  pc.ondatachannel = (ev) => {
    const dc = ev.channel
    dc.onopen = () => console.log('DataChannel open (TS)')
    dc.onmessage = (e) => {
      console.log('Received from Go:', e.data)
      dc.send('hello from TS')
    }
  }

  const offer = readOffer()
  await pc.setRemoteDescription({ type: 'offer', sdp: offer.sdp })
  const answer = await pc.createAnswer()
  await pc.setLocalDescription(answer)
  writeAnswer(answer)
  console.log('Answer written to answer.json, awaiting messages…')
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
}) 