package main

import (
	"encoding/json"
	"fmt"
	"os"

	"gocode/rtc"

	ec "github.com/bitcoin-sv/go-sdk/primitives/ec"
)

func key(byteVal byte) *ec.PrivateKey {
	buf := make([]byte, 32)
	buf[31] = byteVal
	priv, _ := ec.PrivateKeyFromBytes(buf)
	return priv
}

func main() {
	self := key(3)
	peer := key(4)

	raw, sig, salt, err := rtc.BuildHandshake(self, peer.PubKey())
	if err != nil {
		panic(err)
	}

	out := map[string]interface{}{
		"handshake_raw": fmt.Sprintf("%x", raw),
		"handshake_sig": fmt.Sprintf("%x", sig),
		"salt":          fmt.Sprintf("%x", salt),
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
}
