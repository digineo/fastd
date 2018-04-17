package fastd

/*
#cgo pkg-config: libuecc
#include <unistd.h>
#include <libuecc/ecc.h>

// Divides a secret key by 8
// returns 0 on success
static int divide_key(ecc_int256_t *key) {
	uint8_t c = 0, c2;
	ssize_t i;

	for (i = 31; i >= 0; i--) {
		c2 = key->p[i] << 5;
		key->p[i] = (key->p[i] >> 3) | c;
		c = c2;
	}

	return c;
}

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
)

const (
	// KEYSIZE is the length of a public/private key in bytes
	KEYSIZE = 32
)

// KeyPair keeps the secret and public key
type KeyPair struct {
	secret [KEYSIZE]byte
	public [KEYSIZE]byte
}

// RandomKeypair generates a random keypair
func RandomKeypair() (keys *KeyPair) {
	var eccSecret C.ecc_int256_t
	if _, err := rand.Read(eccSecret[:]); err != nil {
		panic(err)
	}

	C.ecc_25519_gf_sanitize_secret(&eccSecret, &eccSecret)
	return NewKeyPair(eccSecret[:])
}

// NewKeyPair generates a keypair from the given secret
func NewKeyPair(secret []byte) *KeyPair {
	keys := &KeyPair{}
	copy(keys.secret[:], secret)
	keys.derivePublic()
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

	C.ecc_25519_scalarmult(&eccWork, &eccSecret, &C.ecc_25519_work_default_base)
	C.ecc_25519_store_packed_legacy(&eccPublic, &eccWork)
	copy(keys.public[:], eccPublic[:])

	// Divide private key
	C.divide_key(&eccSecret)
	copy(keys.secret[:], eccSecret[:])
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

func (hs *handshake) makeSharedKey(serverKey *KeyPair, publicKey []byte) bool {
	A := publicKey
	B := serverKey.public[:]
	X := hs.peerHandshakeKey
	Y := hs.ourHandshakeKey.public[:]

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

	workXY := unpackKey(X)
	eccPeerKey := unpackKey(publicKey)
	var work C.ecc_25519_work_t
	var eb, eccServerKeySecret, eccHandshakeKeySecret, eccSigma C.ecc_int256_t

	copy(eccServerKeySecret[:], serverKey.secret[:])
	copy(eccHandshakeKeySecret[:], hs.ourHandshakeKey.secret[:])

	C.ecc_25519_gf_mult(&eb, &e, &eccServerKeySecret)
	C.ecc_25519_gf_add(&s, &eb, &eccHandshakeKeySecret)
	C.ecc_25519_scalarmult_bits(&work, &d, eccPeerKey, 128)
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
