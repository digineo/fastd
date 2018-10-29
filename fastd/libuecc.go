package fastd

/*
#cgo pkg-config: libuecc
#include <unistd.h>
#include <libuecc/ecc.h>

// Multiplies a point by 8
static void octuple_point(ecc_25519_work_t *p) {
	ecc_25519_work_t work;
	ecc_25519_double(&work, p);
	ecc_25519_double(&work, &work);
	ecc_25519_double(p, &work);
}
*/
import "C"

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

const (
	// KEYSIZE is the length of a public/private key in bytes
	KEYSIZE = 32
)

// KeyPair keeps the secret and public key
type KeyPair struct {
	secret [KEYSIZE]byte // the optimized secret
	public [KEYSIZE]byte
}

// RandomSecret generates a new secret
func RandomSecret() []byte {
	var eccSecret C.ecc_int256_t
	if _, err := rand.Read(eccSecret[:]); err != nil {
		panic(err)
	}

	C.ecc_25519_gf_sanitize_secret(&eccSecret, &eccSecret)
	return eccSecret[:]
}

// RandomKeypair generates a random keypair
func RandomKeypair() *KeyPair {
	return NewKeyPair(RandomSecret())
}

// NewKeyPair generates a keypair from the given secret
func NewKeyPair(secret []byte) *KeyPair {
	keys := &KeyPair{}

	if size := len(secret); size != KEYSIZE {
		panic(fmt.Sprintf("invalid private key size (%d bytes)", size))
	}

	copy(keys.secret[:], secret)
	keys.derivePublic()

	// Divide the secret key by 8 (for some optimizations)
	if !divideKey(&keys.secret) {
		panic("invalid private key")
	}

	return keys
}

// Public returns a copy of the public key.
func (keys *KeyPair) Public() []byte {
	res := make([]byte, KEYSIZE, KEYSIZE)
	copy(res, keys.public[:])
	return res
}

// Derives the public key from the private key and stores it
func (keys *KeyPair) derivePublic() {
	var eccWork C.ecc_25519_work_t
	var eccSecret, eccPublic C.ecc_int256_t

	copy(eccSecret[:], keys.secret[:])
	C.ecc_25519_scalarmult_base(&eccWork, &eccSecret)
	C.ecc_25519_store_packed_legacy(&eccPublic, &eccWork)
	copy(keys.public[:], eccPublic[:])
}

// divides the key by 8
func divideKey(key *[KEYSIZE]byte) bool {
	var c byte

	for i := KEYSIZE - 1; i >= 0; i-- {
		c2 := key[i] << 5
		key[i] = (key[i] >> 3) | c
		c = c2
	}

	return c == 0
}

// unpackKey loads a packed legacy key and returns nil in case of an invalid key.
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

func (hs *Handshake) makeSharedKey(initiator bool, ourKey *KeyPair, peerKey []byte) bool {
	eccPeerKey := unpackKey(peerKey)
	if eccPeerKey == nil {
		return false
	}

	workXY := unpackKey(hs.peerHandshakeKey)
	if workXY == nil || C.ecc_25519_is_identity(workXY) != 0 {
		return false
	}

	var A, B, X, Y []byte

	if initiator {
		A = ourKey.public[:]
		B = peerKey
		X = hs.ourHandshakeKey.public[:]
		Y = hs.peerHandshakeKey
	} else {
		A = peerKey
		B = ourKey.public[:]
		X = hs.peerHandshakeKey
		Y = hs.ourHandshakeKey.public[:]
	}

	hash := sha256.New()
	hash.Write(Y)
	hash.Write(X)
	hash.Write(B)
	hash.Write(A)

	var d, e, s C.ecc_int256_t
	hashSum := hash.Sum(nil)

	copy(d[:], hashSum[:len(hashSum)/2])
	copy(e[:], hashSum[len(hashSum)/2:])

	d[15] |= 0x80
	e[15] |= 0x80

	var work C.ecc_25519_work_t
	var eccOurKeySecret, eccHandshakeKeySecret, eccSigma C.ecc_int256_t

	copy(eccOurKeySecret[:], ourKey.secret[:])
	copy(eccHandshakeKeySecret[:], hs.ourHandshakeKey.secret[:])

	if initiator {
		var da C.ecc_int256_t
		C.ecc_25519_gf_mult(&da, &d, &eccOurKeySecret)
		C.ecc_25519_gf_add(&s, &da, &eccHandshakeKeySecret)
		C.ecc_25519_scalarmult_bits(&work, &e, eccPeerKey, 128)
	} else {
		var eb C.ecc_int256_t
		C.ecc_25519_gf_mult(&eb, &e, &eccOurKeySecret)
		C.ecc_25519_gf_add(&s, &eb, &eccHandshakeKeySecret)
		C.ecc_25519_scalarmult_bits(&work, &d, eccPeerKey, 128)
	}
	C.ecc_25519_add(&work, workXY, &work)

	/*
	  Both our secret keys have been divided by 8 before, so we multiply
	  the point with 8 here to compensate.

	  By multiplying with 8, we prevent small-subgroup attacks (8 is the order
	  of the curves twist, see djb's Curve25519 paper). While the factor 8 should
	  be in the private keys anyways, the reduction modulo the subgroup order (in ecc_25519_gf_*)
	  will only preserve it if the point actually lies on our subgroup.
	*/
	C.octuple_point(&work)

	C.ecc_25519_scalarmult(&work, &s, &work)

	if C.ecc_25519_is_identity(&work) != 0 {
		return false
	}

	// Store sigma
	C.ecc_25519_store_packed_legacy(&eccSigma, &work)
	var sigma [KEYSIZE]byte
	copy(sigma[:], eccSigma[:])

	// Derive shared key
	hs.sharedKey = deriveKey(A, B, X, Y, sigma[:])

	return true
}

func deriveKey(A, B, X, Y, sigma []byte) []byte {
	var info [4*KEYSIZE + 1]byte

	// create info bytes
	copy(info[:], A)
	copy(info[KEYSIZE:], B)
	copy(info[2*KEYSIZE:], X)
	copy(info[3*KEYSIZE:], Y)
	info[len(info)-1] = 0x01

	// extract
	extractor := hmac.New(sha256.New, nil)
	extractor.Write(sigma)
	prk := extractor.Sum(nil)

	// expand
	expander := hmac.New(sha256.New, prk)
	expander.Write(info[:])

	return expander.Sum(nil)
}
