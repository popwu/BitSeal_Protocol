package bitseal

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/bitcoin-sv/go-sdk/message"
	ec "github.com/bitcoin-sv/go-sdk/primitives/ec"
	crypto "github.com/bitcoin-sv/go-sdk/primitives/hash"
)

const ProtocolHeader = "BitSeal"

// RandomNonce returns 128-bit random hex string (32 characters)
func RandomNonce() (string, error) {
	buf := make([]byte, 16)
	_, err := rand.Read(buf)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// CanonicalQueryString implements RFC3986 key-sort encoding
func CanonicalQueryString(q string) string {
	if q == "" {
		return ""
	}
	if strings.HasPrefix(q, "?") {
		q = q[1:]
	}
	values, _ := url.ParseQuery(q)
	type kv struct{ k, v string }
	var kvs []kv
	for k := range values {
		for _, v := range values[k] {
			kvs = append(kvs, kv{k, v})
		}
	}
	sort.Slice(kvs, func(i, j int) bool { return kvs[i].k < kvs[j].k })
	var parts []string
	for _, pair := range kvs {
		parts = append(parts, url.QueryEscape(pair.k)+"="+url.QueryEscape(pair.v))
	}
	return strings.Join(parts, "&")
}

// BodyHashHex returns SHA256(body) in hex or empty string if body is empty
func BodyHashHex(body string) string {
	if body == "" {
		return ""
	}
	hash := crypto.Sha256([]byte(body))
	return hex.EncodeToString(hash)
}

// BuildCanonicalString joins components with newline
func BuildCanonicalString(method, uriPath, query, body, timestamp, nonce string) string {
	parts := []string{
		strings.ToUpper(method),
		uriPath,
		CanonicalQueryString(query),
		BodyHashHex(body),
		timestamp,
		nonce,
	}
	return strings.Join(parts, "\n")
}

// SignRequest constructs headers for a BitSeal request
func SignRequest(method, uriPath, query, body string, clientPriv *ec.PrivateKey, serverPub *ec.PublicKey) (map[string]string, error) {
	timestamp := time.Now().UnixMilli()
	nonce, err := RandomNonce()
	if err != nil {
		return nil, err
	}
	canonical := BuildCanonicalString(method, uriPath, query, body, fmt.Sprintf("%d", timestamp), nonce)
	digest := crypto.Sha256([]byte(canonical))
	sigBytes, err := message.Sign(digest, clientPriv, serverPub)
	if err != nil {
		return nil, err
	}
	sigBase64 := base64.StdEncoding.EncodeToString(sigBytes)
	headers := map[string]string{
		"X-BKSA-Protocol":  ProtocolHeader,
		"X-BKSA-Sig":       sigBase64,
		"X-BKSA-Timestamp": fmt.Sprintf("%d", timestamp),
		"X-BKSA-Nonce":     nonce,
	}
	return headers, nil
}

// VerifyRequest checks headers, returns true if signature OK
func VerifyRequest(method, uriPath, query, body string, headers map[string]string, serverPriv *ec.PrivateKey) (bool, error) {
	if headers["X-BKSA-Protocol"] != ProtocolHeader {
		return false, nil
	}
	timestamp := headers["X-BKSA-Timestamp"]
	nonce := headers["X-BKSA-Nonce"]
	sigBase64 := headers["X-BKSA-Sig"]
	if timestamp == "" || nonce == "" || sigBase64 == "" {
		return false, nil
	}
	canonical := BuildCanonicalString(method, uriPath, query, body, timestamp, nonce)
	msgBytes := []byte(canonical)
	sigBytes, err := base64.StdEncoding.DecodeString(sigBase64)
	if err != nil {
		return false, err
	}
	ok, err := message.Verify(msgBytes, sigBytes, serverPriv)
	if err != nil {
		return false, err
	}
	return ok, nil
}
