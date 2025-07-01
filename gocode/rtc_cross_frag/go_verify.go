package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"gocode/rtc"

	ec "github.com/bitcoin-sv/go-sdk/primitives/ec"
)

type Input struct {
	Digest string   `json:"digest"`
	Frames []string `json:"frames"`
}

func key2(b byte) *ec.PrivateKey {
	buf := make([]byte, 32)
	buf[31] = b
	priv, _ := ec.PrivateKeyFromBytes(buf)
	return priv
}

func main() {
	infile := "frames_ts.json"
	if len(os.Args) > 1 {
		infile = os.Args[1]
	}
	data, err := ioutil.ReadFile(infile)
	if err != nil {
		panic(err)
	}
	var in Input
	if err := json.Unmarshal(data, &in); err != nil {
		panic(err)
	}

	self := key2(1)
	peer := key2(2)
	saltA := []byte{1, 2, 3, 4}
	saltB := []byte{5, 6, 7, 8}

	sess, _ := rtc.NewSession(self, peer.PubKey(), saltA, saltB)
	recv := rtc.NewReassembler(sess)

	var msg []byte
	for _, hexFrame := range in.Frames {
		f, _ := hex.DecodeString(hexFrame)
		if plain, ok, err := recv.Push(f); err != nil {
			panic(err)
		} else if ok {
			msg = plain
		}
	}
	if msg == nil {
		fmt.Println("[Go] failed to reassemble message")
		os.Exit(1)
	}
	digest := sha256.Sum256(msg)
	if hex.EncodeToString(digest[:]) != in.Digest {
		fmt.Println("[Go] digest mismatch")
		os.Exit(1)
	}
	fmt.Println("[Go] cross verification OK ✅")
}
