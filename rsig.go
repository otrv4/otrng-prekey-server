package prekeyserver

import (
	"errors"

	"github.com/coyim/gotrax"
	"github.com/otrv4/ed448"
)

type ringSignature struct {
	c1 ed448.Scalar
	r1 ed448.Scalar
	c2 ed448.Scalar
	r2 ed448.Scalar
	c3 ed448.Scalar
	r3 ed448.Scalar
}

func generateZqKeypair(r gotrax.WithRandom) (ed448.Scalar, ed448.Point) {
	sym := [symKeyLength]byte{}
	gotrax.RandomInto(r, sym[:])
	return deriveZqKeypair(sym)
}

func deriveZqKeypair(sym [symKeyLength]byte) (ed448.Scalar, ed448.Point) {
	kp := gotrax.DeriveKeypair(sym)
	return kp.Priv.K(), kp.Pub.K()
}

func chooseT(Ai ed448.Point, isSecret uint32, Ri ed448.Point, Ti ed448.Point, ci ed448.Scalar) ed448.Point {
	chosen := ed448.PointScalarMul(Ai, ci)
	chosen.Add(Ri, chosen)

	res := ed448.ConstantTimeSelectPoint(chosen, Ti, isSecret)
	return res
}

func calculateC(A1, A2, A3, T1, T2, T3 ed448.Point, msg []byte) ed448.Scalar {
	h := gotrax.KdfPrekeyServer(usageAuth, 64,
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

func generateSignature(wr gotrax.WithRandom, secret *gotrax.PrivateKey, pub *gotrax.PublicKey, A1, A2, A3 *gotrax.PublicKey, m []byte) (*ringSignature, error) {
	r := &ringSignature{}

	isA1 := pub.K().EqualsMask(A1.K())
	isA2 := pub.K().EqualsMask(A2.K())
	isA3 := pub.K().EqualsMask(A3.K())

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

	chosenT1 := chooseT(A1.K(), isA1, R1, T1, c1)
	chosenT2 := chooseT(A2.K(), isA2, R2, T2, c2)
	chosenT3 := chooseT(A3.K(), isA3, R3, T3, c3)

	c := calculateC(A1.K(), A2.K(), A3.K(), chosenT1, chosenT2, chosenT3, m)

	r.c1 = calculateCI(c, c1, isA1, c2, c3)
	r.c2 = calculateCI(c, c2, isA2, c1, c3)
	r.c3 = calculateCI(c, c3, isA3, c1, c2)

	r.r1 = calculateRI(secret.K(), r1, isA1, r.c1, t1)
	r.r2 = calculateRI(secret.K(), r2, isA2, r.c2, t2)
	r.r3 = calculateRI(secret.K(), r3, isA3, r.c3, t3)

	return r, nil
}

func (r *ringSignature) calculateCFromSigma(A1, A2, A3 ed448.Point, msg []byte) ed448.Scalar {
	gr1 := ed448.PrecomputedScalarMul(r.r1)
	gr2 := ed448.PrecomputedScalarMul(r.r2)
	gr3 := ed448.PrecomputedScalarMul(r.r3)

	a1c1 := ed448.PointScalarMul(A1, r.c1)
	a2c2 := ed448.PointScalarMul(A2, r.c2)
	a3c3 := ed448.PointScalarMul(A3, r.c3)

	a1c1.Add(a1c1, gr1)
	a2c2.Add(a2c2, gr2)
	a3c3.Add(a3c3, gr3)

	return calculateC(A1, A2, A3, a1c1, a2c2, a3c3, msg)
}

// verify will do the actual cryptographic validation of the ring signature
func (r *ringSignature) verify(A1, A2, A3 *gotrax.PublicKey, m []byte) bool {
	c := r.calculateCFromSigma(A1.K(), A2.K(), A3.K(), m)
	c1c2c3 := ed448.NewScalar()
	c1c2c3.Add(r.c1, r.c2)
	c1c2c3.Add(c1c2c3, r.c3)

	return c.Equals(c1c2c3)
}
