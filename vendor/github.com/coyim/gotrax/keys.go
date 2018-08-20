package gotrax

import (
	"errors"

	"github.com/otrv4/ed448"
	"golang.org/x/crypto/sha3"
)

type KeyType uint8

const (
	Ed448Key KeyType = iota
	SharedPrekeyKey
)

type Keypair struct {
	Sym  [SymKeyLength]byte
	Priv *PrivateKey
	Pub  *PublicKey
}

type PublicKey struct {
	k       ed448.Point
	keyType KeyType
}

type PrivateKey struct {
	k ed448.Scalar
}

type EddsaSignature struct {
	s [114]byte
}

func (pub *PublicKey) K() ed448.Point {
	return pub.k
}

func (priv *PrivateKey) K() ed448.Scalar {
	return priv.k
}

func (s *EddsaSignature) S() [114]byte {
	return s.s
}

func CreateEddsaSignature(k [114]byte) *EddsaSignature {
	return &EddsaSignature{k}
}

func CreatePublicKey(k ed448.Point, keyType KeyType) *PublicKey {
	return &PublicKey{k, keyType}
}

func CreatePrivateKey(k ed448.Scalar) *PrivateKey {
	return &PrivateKey{k}
}

func GenerateKeypair(r WithRandom) *Keypair {
	sym := [SymKeyLength]byte{}
	RandomInto(r, sym[:])
	return DeriveKeypair(sym)
}

func DeriveKeypair(sym [SymKeyLength]byte) *Keypair {
	digest := [PrivKeyLength]byte{}
	sha3.ShakeSum256(digest[:], sym[:])
	return CreateKeypair(digest, sym)
}

func CreateKeypair(digest [PrivKeyLength]byte, sym [SymKeyLength]byte) *Keypair {
	digest[0] &= -(ed448.Cofactor)
	digest[PrivKeyLength-1] = 0
	digest[PrivKeyLength-2] |= 0x80

	r := ed448.NewScalar(digest[:])

	// We are halving the scalar two times here, because the Ed448 library will
	// multiply it again when we are encoding it in DSA format.

	r.Halve(r)
	r.Halve(r)
	h := ed448.PrecomputedScalarMul(r)

	kp := &Keypair{
		Priv: &PrivateKey{k: r},
		Pub:  &PublicKey{k: h},
	}
	copy(kp.Sym[:], sym[:])

	return kp
}

func ValidatePoint(p ed448.Point) error {
	if p.Equals(IdentityPoint) {
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

type Fingerprint [FingerprintLength]byte

func (kp *Keypair) Fingerprint() Fingerprint {
	return kp.Pub.Fingerprint()
}

func (p *PublicKey) Fingerprint() Fingerprint {
	var f Fingerprint
	Kdfx(usageFingerprint, f[:], p.Serialize())
	return f
}
