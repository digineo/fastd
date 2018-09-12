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
	udpConn    *net.UDPConn
)

func main() {
	log.SetFlags(log.Lshortfile)

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

	udpConn, err = net.DialUDP("udp", nil, addr)
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
	n, err := udpConn.Write(pkt)
	if err != nil {
		log.Fatalf("unable to write to UDP socket: %v", err)
	}
	if n != len(pkt) {
		log.Fatalf("expected to have written %d bytes, wrote %d", len(pkt), n)
	}

	log.Println("waiting for fastd handshake reply")
	reply := waitForPacket(cfg.timeout)

	if verbose {
		log.Println("received payload:", reply.Records)
	}
	local4, e := reply.Records.IPv4Addr()
	if e != nil {
		log.Fatalf("%v", e)
	}
	remote4, e := reply.Records.IPv4DstAddr()
	if e != nil {
		log.Fatalf("%v", e)
	}
	prefix4, e := reply.Records.IPv4PrefixLen()
	if e != nil {
		prefix4 = 31
		log.Printf("%v, assuming /%d", e, prefix4)
	}
	local6, e := reply.Records.IPv6Addr()
	if e != nil {
		log.Fatalf("%v", e)
	}
	remote6, e := reply.Records.IPv6DstAddr()
	if e != nil {
		log.Fatalf("%v", e)
	}
	prefix6, e := reply.Records.IPv6PrefixLen()
	if e != nil {
		prefix6 = 127
		log.Printf("%v, assuming /%d", e, prefix6)
	}

	log.Printf("local   %s/%d   %s/%d", local4, prefix4, local6, prefix6)
	log.Printf("remote  %s/%d   %s/%d", remote4, prefix4, remote6, prefix6)

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

	// create handshake finish 0x03
	finish := reply.NewReply()
	finish.Records.
		SetSenderKey(keyPair.Public()).
		SetRecipientKey(peerKey).
		SetSenderHandshakeKey(hsKey.Public()).
		SetRecipientHandshakeKey(senderHSKey).
		SetMTU(cfg.MTU).
		SetMethodName("null")

	finish.SignKey = hs.SharedKey()

	udpConn.Write(finish.Marshal(false))

	tunnel.Configure(
		cfg.MTU,
		&net.IPNet{IP: local4, Mask: net.CIDRMask(int(prefix4), 32)},
		&net.IPNet{IP: local6, Mask: net.CIDRMask(int(prefix6), 128)},
	)

	go tunnelToUDP()
	go udpToTunnel()

	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	log.Printf("[interrupt received] %s", <-ch)
}

// from fastd tunnel to UDP
func tunnelToUDP() {
	var buf [1500]byte
	buf[0] = byte(fastd.TypeData)
	for {
		n, err := tunnel.Read(buf[1:])
		if err != nil {
			log.Println(err)
			continue
		}
		if verbose {
			log.Printf("got %d bytes from Tunnel", n)
		}

		_, err = udpConn.Write(buf[:n+1])
		if err != nil {
			log.Println(err)
		}
	}
}

// from UDP to fastd tunnel
func udpToTunnel() {
	// disable timeout
	udpConn.SetReadDeadline(time.Time{})

	var buf [1500]byte
	for {
		n, _, err := udpConn.ReadFromUDP(buf[:])
		if err != nil {
			log.Println(err)
			continue
		}
		if verbose {
			log.Printf("got %d bytes from UDP", n)
		}

		_, err = tunnel.Write(buf[1 : n+1])
		if err != nil {
			log.Println(err)
		}
	}
}

func waitForPacket(timeout time.Duration) *fastd.Message {
	buf := make([]byte, 1500)

	udpConn.SetReadDeadline(time.Now().Add(timeout))
	for {
		n, _, err := udpConn.ReadFromUDP(buf)
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
