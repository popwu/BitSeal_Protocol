package rtc

import (
	"encoding/binary"
	"errors"
)

// Application-layer fragmentation (L profile) on top of BST2 session.
// ‑ FRAG_SIZE  = 16 KiB
// ‑ MAX_FRAGS  = 4096  (=> 64 MiB max message)
// Each fragment plaintext = 8-byte header || slice(payload).
// Header Layout (big endian):
//   0       : flags (bit0 = 1 → last fragment)
//   1..3    : msgID (24-bit)
//   4..5    : fragID (uint16, starting 0)
//   6..7    : totalFrags (uint16)
// The fragment header is encrypted together with payload by Session.EncodeRecord().
// Caller is responsible for mapping flags field at BST2 level (we always pass 0).

const (
	FRAG_SIZE = 16 * 1024
	MAX_FRAGS = 4096
	hdrLen    = 8
)

type Fragmenter struct {
	sess      *Session
	nextMsgID uint32 // 24-bit rolling counter
}

func NewFragmenter(sess *Session) *Fragmenter {
	return &Fragmenter{sess: sess, nextMsgID: 0}
}

// Encode splits plaintext into fragments, returns list of BST2 frames ready to send.
func (f *Fragmenter) Encode(plaintext []byte) ([][]byte, error) {
	total := (len(plaintext) + FRAG_SIZE - 1) / FRAG_SIZE
	if total == 0 {
		return nil, nil
	}
	if total > MAX_FRAGS {
		return nil, errors.New("message too large for L profile")
	}
	// rotate msgID 24-bit
	f.nextMsgID = (f.nextMsgID + 1) & 0xFFFFFF
	msgID := f.nextMsgID
	frames := make([][]byte, 0, total)
	for i := 0; i < total; i++ {
		start := i * FRAG_SIZE
		end := start + FRAG_SIZE
		if end > len(plaintext) {
			end = len(plaintext)
		}
		frag := plaintext[start:end]
		flags := byte(0)
		if i == total-1 {
			flags = 0x01 // last fragment flag
		}
		hdr := make([]byte, hdrLen)
		hdr[0] = flags
		put24(hdr[1:4], msgID)
		binary.BigEndian.PutUint16(hdr[4:6], uint16(i))
		binary.BigEndian.PutUint16(hdr[6:8], uint16(total))

		plain := append(hdr, frag...)
		frame, err := f.sess.EncodeRecord(plain, 0)
		if err != nil {
			return nil, err
		}
		frames = append(frames, frame)
	}
	return frames, nil
}

// Reassembler holds state for incoming fragments of one or multiple messages.
// Call Push(frame) for every incoming BST2 frame; when a complete message is
// assembled, it returns (msg, true). Otherwise returns (nil, false).

type Reassembler struct {
	sess *Session
	msgs map[uint32]*msgBuf
}

type msgBuf struct {
	total    uint16
	frags    [][]byte
	received uint16
}

func NewReassembler(sess *Session) *Reassembler {
	return &Reassembler{sess: sess, msgs: make(map[uint32]*msgBuf)}
}

func (r *Reassembler) Push(frame []byte) ([]byte, bool, error) {
	plain, err := r.sess.DecodeRecord(frame)
	if err != nil {
		return nil, false, err
	}
	if len(plain) < hdrLen {
		return nil, false, errors.New("fragment too small")
	}
	flags := plain[0]
	msgID := get24(plain[1:4])
	fragID := binary.BigEndian.Uint16(plain[4:6])
	total := binary.BigEndian.Uint16(plain[6:8])
	data := plain[hdrLen:]

	mb, ok := r.msgs[msgID]
	if !ok {
		mb = &msgBuf{total: total, frags: make([][]byte, total)}
		r.msgs[msgID] = mb
	}
	if int(fragID) >= len(mb.frags) {
		return nil, false, errors.New("fragID overflow")
	}
	if mb.frags[fragID] == nil {
		mb.frags[fragID] = data
		mb.received++
	}
	if flags&0x01 == 1 && mb.received == mb.total {
		// assemble
		full := make([]byte, 0)
		for i := 0; i < int(mb.total); i++ {
			full = append(full, mb.frags[i]...)
		}
		delete(r.msgs, msgID)
		return full, true, nil
	}
	return nil, false, nil
}

// helper: put/get 24-bit big-endian
func put24(b []byte, v uint32) {
	b[0] = byte((v >> 16) & 0xFF)
	b[1] = byte((v >> 8) & 0xFF)
	b[2] = byte(v & 0xFF)
}

func get24(b []byte) uint32 {
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
}
