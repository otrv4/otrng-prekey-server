package gotrax

import (
	"errors"

	"github.com/otrv4/ed448"
)

type RingSignature struct {
	C1 ed448.Scalar
	R1 ed448.Scalar
	C2 ed448.Scalar
	R2 ed448.Scalar
	C3 ed448.Scalar
	R3 ed448.Scalar
}

func generateZqKeypair(r WithRandom) (ed448.Scalar, ed448.Point) {
	sym := [SymKeyLength]byte{}
	RandomInto(r, sym[:])
	return deriveZqKeypair(sym)
}

func deriveZqKeypair(sym [SymKeyLength]byte) (ed448.Scalar, ed448.Point) {
	kp := DeriveKeypair(sym)
	return kp.Priv.k, kp.Pub.k
}

func chooseT(Ai ed448.Point, isSecret uint32, Ri ed448.Point, Ti ed448.Point, ci ed448.Scalar) ed448.Point {
	chosen := ed448.PointScalarMul(Ai, ci)
	chosen.Add(Ri, chosen)

	return ed448.ConstantTimeSelectPoint(chosen, Ti, isSecret)
}

func calculateC(A1, A2, A3, T1, T2, T3 ed448.Point, msg []byte, f KdfFunc, usage uint8) ed448.Scalar {
	h := f(usage, 64,
		basePointBytesDup,
		primeOrderBytesDup,
		A1.DSAEncode(),
		A2.DSAEncode(),
		A3.DSAEncode(),
		T1.DSAEncode(),
		T2.DSAEncode(),
		T3.DSAEncode(),
		msg,
	)

	return ed448.NewScalar(h)
}

func calculateCI(c, ci ed448.Scalar, isSecret uint32, cj, ck ed448.Scalar) ed448.Scalar {
	ifSecret := ed448.NewScalar()
	ifSecret.Sub(c, cj)
	ifSecret.Sub(ifSecret, ck)

	return ed448.ConstantTimeSelectScalar(ci, ifSecret, isSecret)
}

func calculateRI(secret, ri ed448.Scalar, isSecret uint32, ci, ti ed448.Scalar) ed448.Scalar {
	ifSecret := ed448.NewScalar()
	ifSecret.Mul(ci, secret)
	ifSecret.Sub(ti, ifSecret)

	return ed448.ConstantTimeSelectScalar(ri, ifSecret, isSecret)
}

func GenerateSignature(wr WithRandom, secret *PrivateKey, pub *PublicKey, A1, A2, A3 *PublicKey, m []byte, f KdfFunc, usage uint8) (*RingSignature, error) {
	r := &RingSignature{}

	isA1 := pub.k.EqualsMask(A1.k)
	isA2 := pub.k.EqualsMask(A2.k)
	isA3 := pub.k.EqualsMask(A3.k)

	if (isA1 ^ isA2 ^ isA3) == uint32(0) {
		return nil, errors.New("more than one public key match the secret key")
	}

	t1, T1 := generateZqKeypair(wr)
	t2, T2 := generateZqKeypair(wr)
	t3, T3 := generateZqKeypair(wr)

	r1, R1 := generateZqKeypair(wr)
	r2, R2 := generateZqKeypair(wr)
	r3, R3 := generateZqKeypair(wr)

	c1, _ := generateZqKeypair(wr)
	c2, _ := generateZqKeypair(wr)
	c3, _ := generateZqKeypair(wr)

	chosenT1 := chooseT(A1.k, isA1, R1, T1, c1)
	chosenT2 := chooseT(A2.k, isA2, R2, T2, c2)
	chosenT3 := chooseT(A3.k, isA3, R3, T3, c3)

	c := calculateC(A1.k, A2.k, A3.k, chosenT1, chosenT2, chosenT3, m, f, usage)

	r.C1 = calculateCI(c, c1, isA1, c2, c3)
	r.C2 = calculateCI(c, c2, isA2, c1, c3)
	r.C3 = calculateCI(c, c3, isA3, c1, c2)

	r.R1 = calculateRI(secret.k, r1, isA1, r.C1, t1)
	r.R2 = calculateRI(secret.k, r2, isA2, r.C2, t2)
	r.R3 = calculateRI(secret.k, r3, isA3, r.C3, t3)

	return r, nil
}

func (r *RingSignature) calculateCFromSigma(A1, A2, A3 ed448.Point, msg []byte, f KdfFunc, usage uint8) ed448.Scalar {
	gr1 := ed448.PrecomputedScalarMul(r.R1)
	gr2 := ed448.PrecomputedScalarMul(r.R2)
	gr3 := ed448.PrecomputedScalarMul(r.R3)

	a1c1 := ed448.PointScalarMul(A1, r.C1)
	a2c2 := ed448.PointScalarMul(A2, r.C2)
	a3c3 := ed448.PointScalarMul(A3, r.C3)

	a1c1.Add(a1c1, gr1)
	a2c2.Add(a2c2, gr2)
	a3c3.Add(a3c3, gr3)

	return calculateC(A1, A2, A3, a1c1, a2c2, a3c3, msg, f, usage)
}

// Verify will do the actual cryptographic validation of the ring signature
func (r *RingSignature) Verify(A1, A2, A3 *PublicKey, m []byte, f KdfFunc, usage uint8) bool {
	c := r.calculateCFromSigma(A1.k, A2.k, A3.k, m, f, usage)
	c1c2c3 := ed448.NewScalar()
	c1c2c3.Add(r.C1, r.C2)
	c1c2c3.Add(c1c2c3, r.C3)

	return c.Equals(c1c2c3)
}
