package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/digineo/fastd/fastd"
)

var (
	configFile = "./config.json"
	verbose    = false
	tunnel     Interface
)

func main() {
	flag.StringVar(&configFile, "config", configFile, "`PATH` to config file")
	flag.BoolVar(&verbose, "v", verbose, "enable verbose output (warning: contains session keys)")
	flag.Parse()

	cfg, err := readConfig(configFile)
	if err != nil {
		log.Fatalf("cannot read config file %q: %v", configFile, err)
	}
	if err = cfg.Validate(); err != nil {
		log.Fatalf("error validating config: %v", err)
	}

	tunnel, err = newTunDevice()
	if err != nil {
		log.Fatalf("error creating tun device: %v", err)
	}
	defer tunnel.Close()

	addr, err := net.ResolveUDPAddr("udp", cfg.RemoteAddr)
	if err != nil {
		log.Fatalf("unable to resolve %q: %v", cfg.RemoteAddr, err)
	}
	log.Printf("resolved %q to %s", cfg.RemoteAddr, addr)

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
	request.Records.
		SetHandshakeType(fastd.HandshakeRequest).
		SetMode(fastd.ModeTUN).
		SetProtocolName("ec25519-fhmqvc").
		SetSenderKey(keyPair.Public()).
		SetVersionName("v18").
		SetRecipientKey(peerKey).
		SetSenderHandshakeKey(hsKey.Public())

	if hostname, _ := os.Hostname(); hostname != "" {
		request.Records.SetHostname(hostname)
	}

	log.Println("sending fastd handshake request")
	if verbose {
		log.Println("sending payload:", request.Records)
	}

	pkt := request.Marshal(false)
	n, err := conn.Write(pkt)
	if err != nil {
		log.Fatalf("unable to write to UDP socket: %v", err)
	}
	if n != len(pkt) {
		log.Fatalf("expected to have written %d bytes, wrote %d", len(pkt), n)
	}

	log.Println("waiting for fastd handshake reply")
	reply := waitForPacket(conn, cfg.timeout)

	if verbose {
		log.Println("received payload:", reply.Records)
	}

	if typ, e := reply.Records.HandshakeType(); e != nil || typ != fastd.HandshakeReply {
		log.Fatalf("expected finish handshake packet, received %v (err %v)", typ, e)
	}
	if code, e := reply.Records.ReplyCode(); e != nil || code != fastd.ReplySuccess {
		log.Fatalf("expected finish reply type, received %v (err %v)", code, e)
	}

	recipientHSKey, err := reply.Records.RecipientHandshakeKey()
	if err != nil || bytes.Compare(hsKey.Public(), recipientHSKey) != 0 {
		log.Fatalf("recipient handshake key mismatch (err %v)", err)
	}

	senderHSKey, err := reply.Records.SenderHandshakeKey()
	if err != nil || len(senderHSKey) != fastd.KEYSIZE {
		log.Fatalf("invalid sender handshake key size: %d (err %v)", len(senderHSKey), err)
	}

	hs := fastd.NewInitiatingHandshake(keyPair, hsKey, peerKey, senderHSKey)
	reply.SignKey = hs.SharedKey()

	if !reply.VerifySignature() {
		log.Fatal("invalid signature")
	}

	tunnel.Configure(nil, nil, uint16(cfg.MTU))

	// create handshake finish 0x03
	finish := reply.NewReply()
	finish.Records.
		SetSenderKey(keyPair.Public()).
		SetRecipientKey(peerKey).
		SetSenderHandshakeKey(hsKey.Public()).
		SetRecipientHandshakeKey(senderHSKey).
		SetMTU(uint16(cfg.MTU)).
		SetMethodName("null")

	finish.SignKey = hs.SharedKey()

	conn.Write(finish.Marshal(false))

	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	log.Printf("[interrupt received] %s", <-ch)
}

func waitForPacket(conn *net.UDPConn, timeout time.Duration) *fastd.Message {
	buf := make([]byte, 1500)

	conn.SetReadDeadline(time.Now().Add(timeout))
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if verbose {
			log.Printf("got %d bytes", n)
		}
		if err != nil {
			if e, ok := err.(net.Error); !ok || !e.Timeout() {
				log.Fatalf("error reading from UDP socket: %v", err)
			}
			log.Print("reached timeout")
			return nil
		}

		msg, err := fastd.ParseMessage(buf[:n], false)
		if err != nil {
			log.Println("unable to parse message:", err)
		} else {
			return msg
		}
	}
}
