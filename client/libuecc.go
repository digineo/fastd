package main

/*
#cgo pkg-config: libuecc
#include <libuecc-7/libuecc/ecc.h>
*/
import "C"

import (
	"crypto/sha256"
)

const (
	// The length of public/private key in bytes
	KEYSIZE = 32
)

func GetPublic(secret []byte) []byte {
	var eccWork C.ecc_25519_work_t
	var eccSecret, eccPublic C.ecc_int256_t
	var public [32]byte

	copy(eccSecret[:], secret)

	C.ecc_25519_scalarmult(&eccWork, &eccSecret, &C.ecc_25519_work_default_base)
	C.ecc_25519_store_packed_legacy(&eccPublic, &eccWork)

	copy(public[:], eccPublic[:])

	return public[:]
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
		copy(A[:], config.keyPublic)
		//B = &peer_key->key;
		//X = &handshake_key->public;
		copy(Y[:], peerHandshakeKey)
	} else {
		//A = &peer_key->key;
		copy(B[:], config.keyPublic)
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
