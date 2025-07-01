package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"time"

	"gocode/rtc"

	ec "github.com/bitcoin-sv/go-sdk/primitives/ec"
	"github.com/pion/webrtc/v3"
)

type Signal struct {
	SDP  string `json:"sdp"`
	Type string `json:"type"`
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	// Create MediaEngine & SettingEngine for DataChannel only
	m := webrtc.MediaEngine{}
	must(m.RegisterDefaultCodecs())

	api := webrtc.NewAPI(webrtc.WithMediaEngine(&m))

	config := webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{{URLs: []string{"stun:stun.l.google.com:19302"}}},
	}
	peerConnection, err := api.NewPeerConnection(config)
	must(err)

	dc, err := peerConnection.CreateDataChannel("chat", nil)
	must(err)

	// prepare session
	self := key(1)
	peer := key(2)
	saltA := []byte{1, 2, 3, 4}
	saltB := []byte{5, 6, 7, 8}
	sess, _ := rtc.NewSession(self, peer.PubKey(), saltA, saltB)
	recv := rtc.NewReassembler(sess)

	dc.OnOpen(func() {
		fmt.Println("[Go] DataChannel open, waiting for file …")
	})

	var fileName string
	var fileContent []byte

	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		if plain, ok, _ := recv.Push(msg.Data); ok {
			if len(plain) == 0 {
				return
			}
			msgType := plain[0]
			payload := plain[1:]
			if msgType == 1 {
				fileName = string(payload)
				fmt.Println("[Go] Got file name:", fileName)
			} else if msgType == 2 {
				fileContent = make([]byte, len(payload))
				copy(fileContent, payload)
				fmt.Println("[Go] Got file content, bytes:", len(fileContent))
			}
			if fileName != "" && fileContent != nil {
				if err := ioutil.WriteFile(fileName, fileContent, 0644); err != nil {
					fmt.Println("[Go] write file error:", err)
				} else {
					fmt.Println("[Go] File saved to", fileName)
				}
				os.Exit(0)
			}
		}
	})

	// ICE candidate callbacks
	peerConnection.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c != nil {
			fmt.Println("[Go] ICE cand sent:", c.String())
		} else {
			fmt.Println("[Go] ICE gathering complete")
		}
	})

	peerConnection.OnICEConnectionStateChange(func(s webrtc.ICEConnectionState) {
		fmt.Println("[Go] ICE connection state:", s.String())
	})

	peerConnection.OnSignalingStateChange(func(s webrtc.SignalingState) {
		fmt.Println("[Go] SignalingState:", s.String())
	})

	// Create offer
	offer, err := peerConnection.CreateOffer(nil)
	must(err)
	must(peerConnection.SetLocalDescription(offer))

	// wait for ICE gathering complete so that SDP has candidates
	<-webrtc.GatheringCompletePromise(peerConnection)
	local := peerConnection.LocalDescription()

	// Write offer to file
	sig := Signal{SDP: local.SDP, Type: "offer"}
	buf, _ := json.Marshal(sig)
	outPath := filepath.Join("..", "offer.json")
	ioutil.WriteFile(outPath, buf, 0644)
	fmt.Println("Offer written to", outPath, ", waiting for answer.json …")

	peerConnection.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		fmt.Println("Connection state: ", s.String())
		if s == webrtc.PeerConnectionStateConnected {
			fmt.Println("PeerConnection connected ✅")
		}
	})

	// Wait for answer
	for {
		ansPath := filepath.Join("..", "answer.json")
		if _, err := os.Stat(ansPath); err == nil {
			data, _ := ioutil.ReadFile(ansPath)
			var ansSig Signal
			json.Unmarshal(data, &ansSig)
			answer := webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: ansSig.SDP}
			must(peerConnection.SetRemoteDescription(answer))
			break
		}
		time.Sleep(1 * time.Second)
	}

	// Block forever
	select {}
}

func key(b byte) *ec.PrivateKey {
	buf := make([]byte, 32)
	buf[31] = b
	priv, _ := ec.PrivateKeyFromBytes(buf)
	return priv
}
