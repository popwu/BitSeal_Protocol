package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"gocode/rtc"

	ec "github.com/bitcoin-sv/go-sdk/primitives/ec"
)

type In struct {
	HandshakeRaw string `json:"handshake_raw"`
	HandshakeSig string `json:"handshake_sig"`
	Salt         string `json:"salt"`
}

func key(byteVal byte) *ec.PrivateKey {
	buf := make([]byte, 32)
	buf[31] = byteVal
	priv, _ := ec.PrivateKeyFromBytes(buf)
	return priv
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go_rtc_verify <file.json>")
		os.Exit(1)
	}
	data, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var in In
	if err := json.Unmarshal(data, &in); err != nil {
		panic(err)
	}
	raw, _ := hex.DecodeString(in.HandshakeRaw)
	sig, _ := hex.DecodeString(in.HandshakeSig)
	saltPeer, _ := hex.DecodeString(in.Salt)

	self := key(6) // TS 发送时指定的 recipient 私钥
	peerPub := key(5).PubKey()

	peerPubFromMsg, salt, err := rtc.VerifyHandshake(raw, sig, self)
	if err != nil {
		panic(err)
	}
	if !peerPubFromMsg.IsEqual(peerPub) {
		panic("peer pub mismatch")
	}
	_, err = rtc.NewSession(self, peerPub, saltPeer, salt)
	if err != nil {
		panic(err)
	}
	fmt.Println("Go verification OK ✅")
}
