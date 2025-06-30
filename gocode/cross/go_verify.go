package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	bitseal "gocode/bitseal"

	ec "github.com/bitcoin-sv/go-sdk/primitives/ec"
)

type Payload struct {
	Method     string            `json:"method"`
	URIPath    string            `json:"uriPath"`
	Query      string            `json:"query"`
	Body       string            `json:"body"`
	Headers    map[string]string `json:"headers"`
	ServerPriv string            `json:"serverPriv"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: go run go_verify.go <json-file>")
		os.Exit(1)
	}
	file := os.Args[1]
	data, err := ioutil.ReadFile(file)
	if err != nil {
		panic(err)
	}
	var p Payload
	if err := json.Unmarshal(data, &p); err != nil {
		panic(err)
	}

	spBytes, _ := hex.DecodeString(p.ServerPriv)
	serverPriv, _ := ec.PrivateKeyFromBytes(spBytes)
	ok, err := bitseal.VerifyRequest(p.Method, p.URIPath, p.Query, p.Body, p.Headers, serverPriv)
	if err != nil {
		panic(err)
	}
	if ok {
		fmt.Println("Go verify success")
		os.Exit(0)
	}
	fmt.Println("Go verify FAILED")
	os.Exit(1)
}
