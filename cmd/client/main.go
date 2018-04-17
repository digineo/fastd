package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"log"
	"net"
	"os"
	"time"

	"github.com/digineo/fastd/fastd"
)

type config struct {
	RemoteAddr string `json:"remote_addr"`
	RemoteKey  string `json:"remote_key"`
	Secret     string `json:"secret"`
}

var (
	configFile = "./config.json"
)

const readTimeout = 5 * time.Second

func main() {
	flag.StringVar(&configFile, "config", configFile, "`PATH` to config file")
	flag.Parse()

	cfg, err := readConfig(configFile)
	if err != nil {
		log.Fatalf("cannot read config file %q: %v", configFile, err)
	}

	if cfg.RemoteAddr == "" {
		log.Fatalf("config.remote_addr is empty")
	}
	if cfg.RemoteKey == "" {
		log.Fatalf("config.remote_key is empty")
	}
	if cfg.Secret == "" {
		log.Fatalf("config.secret is empty")
	}

	addr, err := net.ResolveUDPAddr("udp", cfg.RemoteAddr)
	if err != nil {
		log.Fatalf("unable to resolve %q: %v", cfg.RemoteAddr, err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Fatalf("DialUDP failed: %v", err)
	}

	secret, err := hex.DecodeString(cfg.Secret)
	if err != nil {
		log.Fatalf("unable to decode secret: %v", err)
	}
	keyPair := fastd.NewKeyPair(secret)

	peerKey, err := hex.DecodeString(cfg.RemoteKey)
	if err != nil {
		log.Fatalf("unable to decode peer key: %v", err)
	}

	msg := fastd.Message{Type: 0x01}
	hsKey := fastd.RandomKeypair()

	msg.Records[fastd.RECORD_HANDSHAKE_TYPE] = []byte{0x01}
	msg.Records[fastd.RECORD_MODE] = []byte{0x01}
	msg.Records[fastd.RECORD_PROTOCOL_NAME] = []byte("ec25519-fhmqvc")
	msg.Records[fastd.RECORD_SENDER_KEY] = keyPair.Public()
	msg.Records[fastd.RECORD_RECIPIENT_KEY] = peerKey
	msg.Records[fastd.RECORD_SENDER_HANDSHAKE_KEY] = hsKey.Public()

	pkt := msg.Marshal(false)

	n, err := conn.Write(pkt)
	if err != nil {
		log.Fatalf("unable to write to UDP socket: %v", err)
	}
	if n != len(pkt) {
		log.Fatalf("expected to have written %d bytes, wrote %d", len(pkt), n)
	}

	conn.SetReadDeadline(time.Now().Add(readTimeout))
	var data bytes.Buffer
	var reply *fastd.Message
	for {
		buf := make([]byte, 1500)
		n, _, err = conn.ReadFromUDP(buf)
		log.Printf("got %d bytes", n)
		if err != nil {
			if e, ok := err.(net.Error); !ok || !e.Timeout() {
				log.Fatalf("error reading from UDP socket: %v", err)
			}
			log.Fatal("reached timeout")
		}

		if n != 0 {
			data.Write(buf[:n])
		}

		reply, err = fastd.ParseMessage(data.Bytes(), false)
		if err != nil {
			log.Printf("not enough bytes to construct reply messages")
		} else {
			break
		}
	}

	if rec := reply.Records[fastd.RECORD_HANDSHAKE_TYPE]; len(rec) != 1 || rec[0] != 0x02 {
		log.Fatalf("expected finish handshake packet, received %v", rec)
	}
	if rec := reply.Records[fastd.RECORD_REPLY_CODE]; len(rec) != 1 || rec[0] != 0x00 {
		log.Fatalf("expected finish reply type, received %v", rec)
	}

	senderHSKey := reply.Records[fastd.RECORD_SENDER_HANDSHAKE_KEY]
	if len(senderHSKey) != fastd.KEYSIZE {
		log.Fatalf("invalid sender handshake key size: %d", len(senderHSKey))
	}

	hs := fastd.NewHandshake(keyPair, hsKey, peerKey, senderHSKey)
	reply.SignKey = hs.SharedKey()

	if !reply.VerifySignature() {
		log.Fatal("invalid signature")
	}

	// create handshake finish 0x03

	finish := reply.NewReply()
	finish.Records[fastd.RECORD_SENDER_KEY] = keyPair.Public()
	finish.Records[fastd.RECORD_RECIPIENT_KEY] = peerKey
	finish.Records[fastd.RECORD_SENDER_HANDSHAKE_KEY] = hsKey.Public()
	finish.Records[fastd.RECORD_RECIPIENT_HANDSHAKE_KEY] = senderHSKey
	finish.SignKey = hs.SharedKey()

}

func readConfig(fname string) (*config, error) {
	f, err := os.Open(configFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg config
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
