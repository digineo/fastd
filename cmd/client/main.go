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

	hsKey := fastd.RandomKeypair()

	// create handshake request 0x01
	request := fastd.Message{Type: 0x01}
	request.Records[fastd.RecordHandshakeType] = []byte{0x01}
	request.Records[fastd.RecordMode] = []byte{0x01}
	request.Records[fastd.RecordProtocolName] = []byte("ec25519-fhmqvc")
	request.Records[fastd.RecordSenderKey] = keyPair.Public()
	request.Records[fastd.RecordVersionName] = []byte("v18")
	request.Records[fastd.RecordRecipientKey] = peerKey
	request.Records[fastd.RecordSenderHandshakeKey] = hsKey.Public()

	if hostname, _ := os.Hostname(); hostname != "" {
		request.Records[fastd.RecordHostname] = []byte(hostname)
	}

	log.Println("Sending:", request.Records)

	pkt := request.Marshal(false)

	n, err := conn.Write(pkt)
	if err != nil {
		log.Fatalf("unable to write to UDP socket: %v", err)
	}
	if n != len(pkt) {
		log.Fatalf("expected to have written %d bytes, wrote %d", len(pkt), n)
	}

	reply := waitForPacket(conn)
	log.Println("Received:", reply.Records)

	if rec := reply.Records[fastd.RecordHandshakeType]; len(rec) != 1 || rec[0] != 0x02 {
		log.Fatalf("expected finish handshake packet, received %v", rec)
	}
	if rec := reply.Records[fastd.RecordReplyCode]; len(rec) != 1 || rec[0] != 0x00 {
		log.Fatalf("expected finish reply type, received %v", rec)
	}

	recipientHSKey := reply.Records[fastd.RecordRecipientHandshakeKey]
	if bytes.Compare(hsKey.Public(), recipientHSKey) != 0 {
		log.Fatalf("recipient handshake key mismatch")
	}

	senderHSKey := reply.Records[fastd.RecordSenderHandshakeKey]
	if len(senderHSKey) != fastd.KEYSIZE {
		log.Fatalf("invalid sender handshake key size: %d", len(senderHSKey))
	}

	hs := fastd.NewInitiatingHandshake(keyPair, hsKey, peerKey, senderHSKey)

	reply.SignKey = hs.SharedKey()

	if !reply.VerifySignature() {
		log.Fatal("invalid signature")
	}

	// create handshake finish 0x03
	finish := reply.NewReply()
	finish.Records[fastd.RecordSenderKey] = keyPair.Public()
	finish.Records[fastd.RecordRecipientKey] = peerKey
	finish.Records[fastd.RecordSenderHandshakeKey] = hsKey.Public()
	finish.Records[fastd.RecordRecipientHandshakeKey] = senderHSKey
	finish.Records[fastd.RecordMethodName] = []byte("null")

	finish.SignKey = hs.SharedKey()

	conn.Write(finish.Marshal(false))
}

func waitForPacket(conn *net.UDPConn) *fastd.Message {
	buf := make([]byte, 1500)

	conn.SetReadDeadline(time.Now().Add(readTimeout))
	for {
		n, _, err := conn.ReadFromUDP(buf)
		log.Printf("got %d bytes", n)
		if err != nil {
			if e, ok := err.(net.Error); !ok || !e.Timeout() {
				log.Fatalf("error reading from UDP socket: %v", err)
			}
			log.Fatal("reached timeout")
		}

		msg, err := fastd.ParseMessage(buf[:n], false)

		if err != nil {
			log.Println("unable to parse message:", err)
		} else {
			return msg
		}
	}
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
