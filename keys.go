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

func (p *publicKey) serialize() []byte {
	return p.k.DSAEncode()
}

func (s *eddsaSignature) serialize() []byte {
	return s.s[:]
}

func serializePoint(p ed448.Point) []byte {
	return p.DSAEncode()
}

var One ed448.Scalar
var OneFourth ed448.Scalar

func init() {
	oneBuf := [privKeyLength]byte{0x01}
	One = ed448.NewScalar(oneBuf[:])
	OneFourth = ed448.NewScalar(oneBuf[:])
	OneFourth.Halve(OneFourth)
	OneFourth.Halve(OneFourth)
}

func deserializePoint(buf []byte) ([]byte, ed448.Point, bool) {
	if len(buf) < 57 {
		return buf, nil, false
	}
	tp := ed448.NewPointFromBytes([]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})
	tp.DSADecode(buf[0:57])
	tp = ed448.PointScalarMul(tp, OneFourth)
	return buf[57:], tp, true
}

func (p *publicKey) deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	buf, p.k, ok = deserializePoint(buf)
	return buf, ok
}

func (s *eddsaSignature) deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	var res []byte
	if buf, res, ok = extractFixedData(buf, 114); !ok {
		return nil, false
	}
	copy(s.s[:], res)
	return buf, true
}

func serializeScalar(s ed448.Scalar) []byte {
	return s.Encode()
}

func deserializeScalar(buf []byte) ([]byte, ed448.Scalar, bool) {
	if len(buf) < 56 {
		return nil, nil, false
	}
	ts := ed448.NewScalar()
	ts.Decode(buf[0:56])
	return buf[56:], ts, true

}
