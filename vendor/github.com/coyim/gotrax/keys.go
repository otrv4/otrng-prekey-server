package gotrax

import (
	"errors"

	"github.com/otrv4/ed448"
	"golang.org/x/crypto/sha3"
)

// KeyType is an OTR key type
type KeyType uint8

const (
	// Ed448Key is a key type for Ed448 keys
	Ed448Key KeyType = iota
	// SharedPrekeyKey is a key type for a shared prekey
	SharedPrekeyKey
	// ForgingKey is a key type for forging keys
	ForgingKey
)

// Keypair represents a standard Elliptic Curve keypair
type Keypair struct {
	Sym  [SymKeyLength]byte
	Priv *PrivateKey
	Pub  *PublicKey
}

// PublicKey represents a standard Elliptic Curve public key, with a keytype
type PublicKey struct {
	k       ed448.Point
	keyType KeyType
}

// PrivateKey represents a standard Elliptic Curve privat key
type PrivateKey struct {
	k ed448.Scalar
}

// EddsaSignature represents a 114-byte EdDSA signature
type EddsaSignature struct {
	s [114]byte
}

// K returns the underlying value
func (pub *PublicKey) K() ed448.Point {
	return pub.k
}

// K returns the underlying value
func (priv *PrivateKey) K() ed448.Scalar {
	return priv.k
}

// S returns the underlying value
func (s *EddsaSignature) S() [114]byte {
	return s.s
}

// CreateEddsaSignature will create a new EddsaSignature object from the given bytes
func CreateEddsaSignature(k [114]byte) *EddsaSignature {
	return &EddsaSignature{k}
}

// CreatePublicKey will create a new public key from the given values
func CreatePublicKey(k ed448.Point, keyType KeyType) *PublicKey {
	return &PublicKey{k, keyType}
}

// CreatePrivateKey will create a new private key from the given value
func CreatePrivateKey(k ed448.Scalar) *PrivateKey {
	return &PrivateKey{k}
}

// GenerateKeypair will create a new keypair from the given randomness
func GenerateKeypair(r WithRandom) *Keypair {
	sym := [SymKeyLength]byte{}
	RandomInto(r, sym[:])
	return DeriveKeypair(sym)
}

// DeriveKeypair will create a new keypair derived from the bytes given
func DeriveKeypair(sym [SymKeyLength]byte) *Keypair {
	digest := [PrivKeyLength]byte{}
	sha3.ShakeSum256(digest[:], sym[:])
	return CreateKeypair(digest, sym)
}

// CreateKeypair will create a new keypair from the private digest and bytes given
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

// ValidatePoint returns an error if the point can't be validated according to standard ECC algorithms
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

// Fingerprint is a set of bytes representing a longer public key
type Fingerprint [FingerprintLength]byte

// Fingerprint will generate a fingerprint from the keypair's public key
func (kp *Keypair) Fingerprint() Fingerprint {
	return kp.Pub.Fingerprint()
}

// Fingerprint will return an OTR fingerprint from the public key
func (pub *PublicKey) Fingerprint() Fingerprint {
	var f Fingerprint
	Kdfx(usageFingerprint, f[:], pub.Serialize())
	return f
}
