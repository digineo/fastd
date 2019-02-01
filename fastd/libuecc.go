package fastd

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/digineo/go-libuecc"
)

/*
By multiplying with 8, we prevent small-subgroup attacks (8 is the order
of the curves twist, see djb's Curve25519 paper). While the factor 8 should
be in the private keys anyways, the reduction modulo the subgroup order (in ecc_25519_gf_*)
will only preserve it if the point actually lies on our subgroup.
*/
func octuplePoint(p *libuecc.Point) *libuecc.Point {
	return p.Double().Double().Double()
}

const (
	// KEYSIZE is the length of a public/private key in bytes
	KEYSIZE = 32
)

// KeyPair keeps the secret and public key
type KeyPair struct {
	secret *libuecc.Int256 // the optimized secret
	public *libuecc.Int256
}

// RandomSecret generates a new secret
func RandomSecret() *libuecc.Int256 {
	buf := make([]byte, KEYSIZE)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}

	return libuecc.NewInt256(buf).SanitizeSecret()
}

// RandomKeypair generates a random keypair
func RandomKeypair() *KeyPair {
	return keyPairFromSecret(RandomSecret())
}

// NewKeyPair generates a keypair from the given secret
func NewKeyPair(secret []byte) *KeyPair {
	if size := len(secret); size != KEYSIZE {
		panic(fmt.Sprintf("invalid private key size (%d bytes)", size))
	}

	return keyPairFromSecret(libuecc.NewInt256(secret))
}

func keyPairFromSecret(secret *libuecc.Int256) *KeyPair {
	keys := &KeyPair{secret: secret}
	keys.derivePublic()

	// Divide the secret key by 8 (for some optimizations)
	if !divideKey(keys.secret) {
		panic("invalid private key")
	}

	return keys
}

// Public returns a copy of the public key.
func (keys *KeyPair) Public() []byte {
	return keys.public.Bytes()
}

// divides the key by 8
func divideKey(key *libuecc.Int256) bool {
	var c byte

	for i := KEYSIZE - 1; i >= 0; i-- {
		c2 := key[i] << 5
		key[i] = (key[i] >> 3) | c
		c = c2
	}

	return c == 0
}

// Derives the public key from the private key and stores it
func (keys *KeyPair) derivePublic() {
	temp := libuecc.PointBaseLegacy()
	work := temp.ScalarMult(keys.secret)

	keys.public = work.StorePackedLegacy()
}

// unpackKey loads a packed legacy key and returns nil in case of an invalid key.
func unpackKey(key []byte) *libuecc.Point {
	unpacked := libuecc.NewInt256(key).LoadPackedLegacy()
	if unpacked == nil || unpacked.IsIdentity() {
		return nil
	}
	return unpacked
}

func (hs *Handshake) makeSharedKey(initiator bool, ourKey *KeyPair, peerKey []byte) bool {
	eccPeerKey := unpackKey(peerKey)
	if eccPeerKey == nil {
		return false
	}

	workXY := unpackKey(hs.peerHandshakeKey)
	if workXY == nil {
		return false
	}

	var A, B, X, Y []byte

	if initiator {
		A = ourKey.public.Bytes()
		B = peerKey
		X = hs.ourHandshakeKey.public.Bytes()
		Y = hs.peerHandshakeKey
	} else {
		A = peerKey
		B = ourKey.public.Bytes()
		X = hs.peerHandshakeKey
		Y = hs.ourHandshakeKey.public.Bytes()
	}

	hash := sha256.New()
	hash.Write(Y)
	hash.Write(X)
	hash.Write(B)
	hash.Write(A)

	var d, e libuecc.Int256
	hashSum := hash.Sum(nil)

	copy(d[:], hashSum[:len(hashSum)/2])
	copy(e[:], hashSum[len(hashSum)/2:])

	d[15] |= 0x80
	e[15] |= 0x80

	var work *libuecc.Point
	var eccOurKeySecret, eccHandshakeKeySecret libuecc.Int256

	copy(eccOurKeySecret[:], ourKey.secret[:])
	copy(eccHandshakeKeySecret[:], hs.ourHandshakeKey.secret[:])

	var s *libuecc.Int256
	if initiator {
		da := d.GfMult(&eccOurKeySecret)
		s = da.GfAdd(&eccHandshakeKeySecret)
		work = eccPeerKey.ScalarMultBits(&e, 128)
	} else {
		eb := e.GfMult(&eccOurKeySecret)
		s = eb.GfAdd(&eccHandshakeKeySecret)
		work = eccPeerKey.ScalarMultBits(&d, 128)
	}
	work = workXY.Add(work)

	/*
	  Both our secret keys have been divided by 8 before, so we multiply
	  the point with 8 here to compensate.
	*/
	work = octuplePoint(work)
	work = work.ScalarMult(s)

	if work.IsIdentity() {
		return false
	}

	// Store sigma
	eccSigma := work.StorePackedLegacy()
	sigma := eccSigma.Bytes()

	// Derive shared key
	hs.sharedKey = deriveKey(A, B, X, Y, sigma[:])

	return true
}

func deriveKey(A, B, X, Y, sigma []byte) []byte {
	// extract
	extractor := hmac.New(sha256.New, nil)
	extractor.Write(sigma)
	prk := extractor.Sum(nil)

	// expand
	expander := hmac.New(sha256.New, prk)
	expander.Write(A)
	expander.Write(B)
	expander.Write(X)
	expander.Write(Y)
	expander.Write([]byte{0x01})

	return expander.Sum(nil)
}
