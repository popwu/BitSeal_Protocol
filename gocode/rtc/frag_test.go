package rtc

import (
	"bytes"
	"crypto/rand"
	"testing"

	ec "github.com/bitcoin-sv/go-sdk/primitives/ec"
)

func TestFragmentRoundtrip(t *testing.T) {
	// build deterministic keys (32 bytes with last byte diff)
	privABytes := bytes.Repeat([]byte{0}, 32)
	privABytes[31] = 1 // ensure non-zero scalar
	privA, _ := ec.PrivateKeyFromBytes(privABytes)

	privBBytes := bytes.Repeat([]byte{0}, 32)
	privBBytes[31] = 2
	privB, _ := ec.PrivateKeyFromBytes(privBBytes)

	saltA := []byte{1, 2, 3, 4}
	saltB := []byte{5, 6, 7, 8}

	sessA, err := NewSession(privA, privB.PubKey(), saltA, saltB)
	if err != nil {
		t.Fatal(err)
	}
	sessB, err := NewSession(privB, privA.PubKey(), saltA, saltB)
	if err != nil {
		t.Fatal(err)
	}

	fragA := NewFragmenter(sessA)
	recvB := NewReassembler(sessB)

	// random 1MB payload
	msg := make([]byte, 1<<20)
	_, _ = rand.Read(msg)

	frames, err := fragA.Encode(msg)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range frames {
		plain, ok, err := recvB.Push(f)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			if !bytes.Equal(plain, msg) {
				t.Fatal("mismatch after roundtrip")
			}
			return
		}
	}
	t.Fatal("message not reassembled")
}
