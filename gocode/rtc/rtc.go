package rtc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bitcoin-sv/go-sdk/message"
	ec "github.com/bitcoin-sv/go-sdk/primitives/ec"
	crypto "github.com/bitcoin-sv/go-sdk/primitives/hash"
)

// Constants
const (
	protoString = "BitSeal-RTC/1.0"
	tagSize     = 16
)

type HandshakeMsg struct {
	Proto string `json:"proto"`
	PK    string `json:"pk"`   // compressed hex
	Salt  string `json:"salt"` // 4 bytes hex
	Ts    int64  `json:"ts"`
}

// BuildHandshake creates and signs a handshake payload.
func BuildHandshake(selfPriv *ec.PrivateKey, peerPub *ec.PublicKey) ([]byte, []byte, []byte, error) {
	// 4-byte salt
	salt := make([]byte, 4)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, nil, err
	}
	msg := HandshakeMsg{
		Proto: protoString,
		PK:    hex.EncodeToString(selfPriv.PubKey().Compressed()),
		Salt:  hex.EncodeToString(salt),
		Ts:    time.Now().UnixMilli(),
	}
	raw, _ := json.Marshal(msg)
	digest := crypto.Sha256(raw)
	sig, err := message.Sign(digest, selfPriv, peerPub)
	if err != nil {
		return nil, nil, nil, err
	}
	return raw, sig, salt, nil
}

// VerifyHandshake verifies peer handshake and returns peer pubkey & salt.
func VerifyHandshake(raw, sig []byte, selfPriv *ec.PrivateKey) (*ec.PublicKey, []byte, error) {
	// parse
	var msg HandshakeMsg
	if err := json.Unmarshal(raw, &msg); err != nil {
		return nil, nil, err
	}
	if msg.Proto != protoString {
		return nil, nil, errors.New("protocol mismatch")
	}
	peerPubBytes, err := hex.DecodeString(msg.PK)
	if err != nil {
		return nil, nil, err
	}
	peerPub, err := ec.ParsePubKey(peerPubBytes)
	if err != nil {
		return nil, nil, err
	}
	ok, err := message.Verify(raw, sig, selfPriv)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, errors.New("signature invalid")
	}
	saltBytes, err := hex.DecodeString(msg.Salt)
	if err != nil {
		return nil, nil, err
	}
	return peerPub, saltBytes, nil
}

// Session represents an established BST2 session.
type Session struct {
	key        []byte // 32-byte AES key
	salt       []byte // 4 bytes
	seq        uint64 // send seq
	recvWindow *window
	aead       cipher.AEAD
}

type window struct {
	size   uint64
	maxSeq uint64
	bitmap uint64 // supports up to 64
}

// deriveKey derives 32-byte session key from shared secret + salts.
func deriveKey(shared, saltA, saltB []byte) []byte {
	data := append(shared, saltA...)
	data = append(data, saltB...)
	return crypto.Sha256(data)
}

// NewSession creates session after both handshakes exchanged.
func NewSession(selfPriv *ec.PrivateKey, peerPub *ec.PublicKey, selfSalt, peerSalt []byte) (*Session, error) {
	sharedPoint, err := selfPriv.DeriveSharedSecret(peerPub)
	if err != nil {
		return nil, err
	}
	sharedBytes := sharedPoint.Compressed()
	key := deriveKey(sharedBytes, selfSalt, peerSalt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// initialize send sequence with random 64-bit value (seq_init)
	randBytes := make([]byte, 8)
	if _, err := rand.Read(randBytes); err != nil {
		return nil, err
	}
	initSeq := binary.BigEndian.Uint64(randBytes)

	return &Session{
		key:        key,
		salt:       selfSalt,
		seq:        initSeq,
		recvWindow: &window{size: 64, maxSeq: 0, bitmap: 0},
		aead:       aead,
	}, nil
}

// EncodeRecord encrypts plaintext into a BST2 frame.
func (s *Session) EncodeRecord(plaintext []byte, flags byte) ([]byte, error) {
	s.seq++
	seqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBytes, s.seq)
	nonce := append(s.salt, seqBytes...)
	ad := append([]byte{flags}, seqBytes...)
	cipherText := s.aead.Seal(nil, nonce, plaintext, ad)
	// split tag
	tag := cipherText[len(cipherText)-tagSize:]
	cipherTextOnly := cipherText[:len(cipherText)-tagSize]
	length := uint32(1 + 8 + uint32(len(cipherTextOnly)) + tagSize)

	buf := make([]byte, 4+1+8+len(cipherTextOnly)+tagSize)
	binary.BigEndian.PutUint32(buf[0:4], length)
	buf[4] = flags
	copy(buf[5:13], seqBytes)
	copy(buf[13:13+len(cipherTextOnly)], cipherTextOnly)
	copy(buf[13+len(cipherTextOnly):], tag)
	return buf, nil
}

// DecodeRecord decrypts frame and returns plaintext.
func (s *Session) DecodeRecord(frame []byte) ([]byte, error) {
	if len(frame) < 4+1+8+tagSize {
		return nil, errors.New("frame too short")
	}
	length := binary.BigEndian.Uint32(frame[:4])
	if int(length) != len(frame[4:]) {
		return nil, fmt.Errorf("length mismatch: %d vs %d", length, len(frame[4:]))
	}
	flags := frame[4]
	seq := binary.BigEndian.Uint64(frame[5:13])
	// replay window check
	if !s.recvWindow.accept(seq) {
		return nil, errors.New("replay or old packet")
	}
	cipherTextOnly := frame[13 : len(frame)-tagSize]
	tag := frame[len(frame)-tagSize:]
	seqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBytes, seq)
	nonce := append(s.salt, seqBytes...)
	ad := append([]byte{flags}, seqBytes...)
	cipherWithTag := append(cipherTextOnly, tag...)
	plain, err := s.aead.Open(nil, nonce, cipherWithTag, ad)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

func (w *window) accept(seq uint64) bool {
	if seq > w.maxSeq {
		shift := seq - w.maxSeq
		if shift >= w.size {
			w.bitmap = 0
		} else {
			w.bitmap <<= shift
		}
		w.bitmap |= 1
		w.maxSeq = seq
		return true
	}
	offset := w.maxSeq - seq
	if offset >= w.size {
		return false
	}
	if (w.bitmap>>offset)&1 == 1 {
		return false
	}
	w.bitmap |= (1 << offset)
	return true
}
