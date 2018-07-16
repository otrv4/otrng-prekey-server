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

func generateKeypair(r WithRandom) *keypair {
	sym := [symKeyLength]byte{}
	randomInto(r, sym[:])
	return deriveKeypair(sym)
}

func deriveKeypair(sym [symKeyLength]byte) *keypair {
	digest := [privKeyLength]byte{}
	sha3.ShakeSum256(digest[:], sym[:])
	return createKeypair(digest, sym)
}

func createKeypair(digest [privKeyLength]byte, sym [symKeyLength]byte) *keypair {
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
	kdfOtrv4(usageFingerprint, f[:], rep)
	return f
}

func validatePoint(p ed448.Point) error {
	if p.Equals(identityPoint) {
		return errors.New("given point is the identity point")
	}

	if !p.IsOnCurve() {
		return errors.New("given point is not on the curve")
	}

	// Here the spec says we should check for a small subgroup
	// attack by verifying q P == I. However, since the ed448
	// implementation is using decaf for internal representation,
	// and this internal representation has cofactor 1, the
	// small subgroup check is implied by the above two conditions,
	// and thus not necessary.

	return nil
}

func (kp *keypair) Fingerprint() []byte {
	v := kp.fingerprint()
	return v[:]
}

func (kp *keypair) realKeys() *keypair {
	return kp
}
