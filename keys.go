package prekeyserver

import (
	"errors"

	"github.com/otrv4/ed448"
	"golang.org/x/crypto/sha3"
)

// keypair represents and can be used for either an ecdh keypair, or for an eddsa keypiar
// the key generation is slightly different, but the struct retains all needed information
type keypair struct {
	sym  [symKeyLength]byte
	priv *privateKey
	pub  *publicKey
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

	kp := &keypair{
		priv: &privateKey{k: r},
		pub:  &publicKey{k: h},
	}
	copy(kp.sym[:], sym[:])

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

func validatePoint(p ed448.Point) error {
	if p.Equals(identityPoint) {
		return errors.New("given point is the identity point")
	}

	// TODO: implement fully
	return nil
}
