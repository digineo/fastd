package main

/*
#cgo pkg-config: libuecc
#include <libuecc-7/libuecc/ecc.h>
*/
import "C"

import (
	"crypto/rand"
	"crypto/sha256"
	"golang.org/x/crypto/hkdf"
	"io"
)

const (
	// The length of public/private key in bytes
	KEYSIZE = 32
)

type KeyPair struct {
	secret [KEYSIZE]byte
	public [KEYSIZE]byte
}

// Generates a random keypair
func RandomKeypair() (keys KeyPair) {
	var eccSecret C.ecc_int256_t
	if _, err := rand.Read(eccSecret[:]); err != nil {
		panic(err)
	}

	C.ecc_25519_gf_sanitize_secret(&eccSecret, &eccSecret)
	copy(keys.secret[:], eccSecret[:])
	keys.derivePublic()

	return
}

// Generates a keypair from the given secret
func NewKeyPair(secret []byte) KeyPair {
	keys := KeyPair{}
	copy(keys.secret[:], secret)
	keys.derivePublic()
	return keys
}

// Derives the public key from the private key and stores it
func (keys *KeyPair) derivePublic() {
	var eccWork C.ecc_25519_work_t
	var eccSecret, eccPublic C.ecc_int256_t

	copy(eccSecret[:], keys.secret[:])

	C.ecc_25519_scalarmult(&eccWork, &eccSecret, &C.ecc_25519_work_default_base)
	C.ecc_25519_store_packed_legacy(&eccPublic, &eccWork)

	copy(keys.public[:], eccPublic[:])
}

func unpackKey(key []byte) *C.ecc_25519_work_t {
	var eccKey C.ecc_int256_t
	var unpacked C.ecc_25519_work_t

	copy(eccKey[:], key)
	if C.ecc_25519_load_packed_legacy(&unpacked, &eccKey) != 1 {
		return nil
	}

	if C.ecc_25519_is_identity(&unpacked) != 0 {
		return nil
	}

	return &unpacked
}

func makeSharedHandshakeKey(peer *Peer) bool {

	A := peer.publicKey
	B := config.serverKeys.public[:]
	X := peer.peerHandshakeKey
	Y := peer.handshakeKey.public[:]

	hash := sha256.New()
	hash.Write(Y[:])
	hash.Write(X[:])
	hash.Write(B[:])
	hash.Write(A[:])

	var d, e, s C.ecc_int256_t
	hashSum := hash.Sum([]byte{})

	copy(d[:], hashSum[:len(hashSum)/2])
	copy(e[:], hashSum[len(hashSum)/2:])

	d[15] |= 0x80
	e[15] |= 0x80

	workXY := unpackKey(peer.peerHandshakeKey)
	eccPeerKey := unpackKey(peer.publicKey)
	var work C.ecc_25519_work_t
	var eb, eccServerKeySecret, eccHandshakeKeySecret, eccSigma C.ecc_int256_t

	copy(eccServerKeySecret[:], config.serverKeys.secret[:])
	copy(eccHandshakeKeySecret[:], peer.handshakeKey.secret[:])

	C.ecc_25519_gf_mult(&eb, &e, &eccServerKeySecret)
	C.ecc_25519_gf_add(&s, &eb, &eccHandshakeKeySecret)
	C.ecc_25519_scalarmult_bits(&work, &d, eccPeerKey, 128)
	C.ecc_25519_add(&work, workXY, &work)

	// TODO octuple_point(&work)

	C.ecc_25519_scalarmult(&work, &s, &work)

	if C.ecc_25519_is_identity(&work) != 0 {
		return false
	}

	// Store sigma
	C.ecc_25519_store_packed_legacy(&eccSigma, &work)
	var sigma []byte
	copy(sigma, eccSigma[:])

	// Derive shared key
	peer.sharedKey = deriveKey(A, B, X, Y, sigma)

	return true
}

func deriveKey(A, B, X, Y, sigma []byte) []byte {
	var info [4 * KEYSIZE]byte

	copy(info[:], A)
	copy(info[:KEYSIZE], B)
	copy(info[:2*KEYSIZE], X)
	copy(info[:3*KEYSIZE], Y)

	key := make([]byte, KEYSIZE)
	hkdf := hkdf.New(sha256.New, sigma, nil, info[:])
	_, err := io.ReadFull(hkdf, key)
	if err != nil {
		panic(err)
	}

	return key
}
