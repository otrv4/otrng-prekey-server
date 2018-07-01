package prekeyserver

import (
	"github.com/twstrike/ed448"
	"golang.org/x/crypto/sha3"
)

const symKeyLength = 57
const privKeyLength = 57
const fingerprintLength = 56

const usageFingerprint = 0x00
const usageSK = 0x01

// keypair represents and can be used for either an ecdh keypair, or for an eddsa keypiar
// the key generation is slightly different, but the struct retains all needed information
type keypair struct {
	sym  [symKeyLength]byte
	priv privateKey
	pub  publicKey
}

type publicKey struct {
	k ed448.Point
}

type privateKey struct {
	k ed448.Scalar
}

type eddsaSignature struct {
	s [114]byte
}

func generateEDDSAKeypair(r WithRandom) *keypair {
	sym := [symKeyLength]byte{}
	randomInto(r, sym[:])
	return deriveEDDSAKeypair(sym)
}

func generateECDHKeypair(r WithRandom) *keypair {
	sym := [symKeyLength]byte{}
	randomInto(r, sym[:])
	return deriveECDHKeypair(sym)
}

func deriveEDDSAKeypair(sym [symKeyLength]byte) *keypair {
	digest := [privKeyLength]byte{}
	sha3.ShakeSum256(digest[:], sym[:])
	return deriveKeypair(digest, sym)
}

func deriveECDHKeypair(sym [symKeyLength]byte) *keypair {
	// This implementation is based on the current libotr-ng implementation. IT IS NOT CORRECT.
	digest := [privKeyLength]byte{}
	kdf_otrv4(usageSK, digest[:], sym[:])
	return deriveEDDSAKeypair(digest)
}

func deriveKeypair(digest [privKeyLength]byte, sym [symKeyLength]byte) *keypair {
	digest[0] &= -(ed448.Cofactor)
	digest[privKeyLength-1] = 0
	digest[privKeyLength-2] |= 0x80

	r := ed448.NewScalar(digest[:])

	// We are halving the scalar two times here, because the Ed448 library will
	// multiply it again when we are encoding it in DSA format.

	r.Halve(r)
	r.Halve(r)
	h := ed448.PrecomputedScalarMul(r)

	kp := &keypair{}
	copy(kp.sym[:], sym[:])
	kp.priv.k = r
	kp.pub.k = h

	return kp
}

type fingerprint [fingerprintLength]byte

func (kp *keypair) fingerprint() fingerprint {
	return kp.pub.fingerprint()
}

func (p *publicKey) fingerprint() fingerprint {
	var f fingerprint
	rep := p.k.DSAEncode()
	kdf_otrv4(usageFingerprint, f[:], rep)
	return f
}
