package main

/*
#cgo pkg-config: libuecc
#include <libuecc-7/libuecc/ecc.h>
*/
import "C"

import (
	"crypto/rand"
	"crypto/sha256"
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

func makeSharedHandshakeKey(initiator bool, peerHandshakeKey []byte) bool {
	var workXY C.ecc_25519_work_t
	var eccPeerHandshakeKey C.ecc_int256_t

	copy(eccPeerHandshakeKey[:], peerHandshakeKey)

	if C.ecc_25519_load_packed_legacy(&workXY, &eccPeerHandshakeKey) != 1 {
		return false
	}

	if C.ecc_25519_is_identity(&workXY) != 0 {
		return false
	}

	var A, B, X, Y C.ecc_int256_t

	if initiator {
		copy(A[:], config.serverKeys.public[:])
		//B = &peer_key->key;
		//X = &handshake_key->public;
		copy(Y[:], peerHandshakeKey)
	} else {
		//A = &peer_key->key;
		copy(B[:], config.serverKeys.public[:])
		copy(X[:], peerHandshakeKey)
		//Y = &handshake_key->public;
	}

	hash := sha256.New()
	hash.Write(Y[:])
	hash.Write(X[:])
	hash.Write(B[:])
	hash.Write(A[:])

	var d, e C.ecc_int256_t
	hashSum := hash.Sum([]byte{})

	copy(d[:], hashSum[:len(hashSum)/2])
	copy(e[:], hashSum[len(hashSum)/2:])

	// TODO

	return true
}
