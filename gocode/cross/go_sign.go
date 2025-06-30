package main

import (
	"encoding/json"
	"fmt"
	"os"

	bitseal "gocode/bitseal"

	ec "github.com/bitcoin-sv/go-sdk/primitives/ec"
)

func fixedPrivKey(byteVal byte) *ec.PrivateKey {
	buf := make([]byte, 32)
	buf[31] = byteVal
	priv, _ := ec.PrivateKeyFromBytes(buf)
	return priv
}

func main() {
	method := "POST"
	uriPath := "/test"
	query := ""
	body := "{\"hello\":\"world\"}"

	clientPriv := fixedPrivKey(1)
	serverPriv := fixedPrivKey(2)
	headers, err := bitseal.SignRequest(method, uriPath, query, body, clientPriv, serverPriv.PubKey())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	out := map[string]interface{}{
		"method":     method,
		"uriPath":    uriPath,
		"query":      query,
		"body":       body,
		"headers":    headers,
		"serverPriv": fmt.Sprintf("%x", serverPriv.Serialize()),
	}
	json.NewEncoder(os.Stdout).Encode(out)
}
