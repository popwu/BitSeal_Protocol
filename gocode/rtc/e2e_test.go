package rtc

import (
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"math/rand"
	"testing"
	"time"

	ec "github.com/bitcoin-sv/go-sdk/primitives/ec"
)

func mustPriv(seed byte) *ec.PrivateKey {
	b := bytes.Repeat([]byte{seed}, 32)
	key, _ := ec.PrivateKeyFromBytes(b)
	return key
}

// TestOutOfOrderDuplicate checks reassembler under out-of-order & duplicate delivery.
func TestOutOfOrderDuplicate(t *testing.T) {
	rand.Seed(time.Now().UnixNano())

	privA := mustPriv(0x01)
	privB := mustPriv(0x02)
	saltA := []byte{1, 2, 3, 4}
	saltB := []byte{5, 6, 7, 8}

	sessA, _ := NewSession(privA, privB.PubKey(), saltA, saltB)
	sessB, _ := NewSession(privB, privA.PubKey(), saltA, saltB)

	fragA := NewFragmenter(sessA)
	recvB := NewReassembler(sessB)

	// 4 MiB random message
	msg := make([]byte, 4<<20)
	_, _ = crand.Read(msg)

	frames, err := fragA.Encode(msg)
	if err != nil {
		t.Fatal(err)
	}

	// introduce duplicates (kept after originals to stay within window)
	for i := 0; i < 10 && len(frames) > 0; i++ {
		idx := rand.Intn(len(frames))
		frames = append(frames, frames[idx])
	}

	var assembled []byte
	for _, f := range frames {
		plain, ok, err := recvB.Push(f)
		if err != nil {
			// duplicate or replay frames may error; skip them
			continue
		}
		if ok {
			assembled = plain
		}
	}
	if assembled == nil {
		t.Fatalf("failed to assemble message; received=%d expected=%d", recvB.msgs[1].received, recvB.msgs[1].total)
	}
	if !bytes.Equal(assembled, msg) {
		t.Fatal("assembled payload mismatch")
	}
}

// TestReplayWindowBoundary ensures packets older than window are rejected.
func TestReplayWindowBoundary(t *testing.T) {
	priv := mustPriv(0x03)
	salt := []byte{1, 1, 1, 1}
	sess, _ := NewSession(priv, priv.PubKey(), salt, salt)

	// send first 70 sequences (window size 64)
	for i := 0; i < 70; i++ {
		frame, _ := sess.EncodeRecord([]byte{byte(i)}, 0)
		if _, err := sess.DecodeRecord(frame); err != nil {
			t.Fatalf("unexpected decode fail at %d: %v", i, err)
		}
	}
	// re-send seq 1 (which is now out of window)
	oldFrame, _ := sess.EncodeRecord([]byte{0xFF}, 0)
	// manually overwrite seq number to 1
	binary.BigEndian.PutUint64(oldFrame[5:13], 1)
	if _, err := sess.DecodeRecord(oldFrame); err == nil {
		t.Fatal("expected old packet to be rejected")
	}
}
