package prekeyserver

import (
	"bytes"
	"crypto/rand"
	"math/big"

	"github.com/coyim/gotrax"
	"github.com/otrv4/ed448"
)

type ecdhProof struct {
	c []byte
	v ed448.Scalar
}

type dhProof struct {
	c []byte
	v *big.Int
}

const lambda = uint32(352 / 8) // 44 bytes

func generateRandomExponent(order *big.Int, wr gotrax.WithRandom) *big.Int {
	for {
		n, err := rand.Int(wr.RandReader(), order)
		if err != nil {
			return nil
		}
		if n.Cmp(one) > 0 {
			return n
		}
	}
}

// splitBufferIntoN will split b into n even sized units
// the buffer HAS to be evenly divisible into n
func splitBufferIntoN(b []byte, n uint) [][]byte {
	eachLen := uint(len(b)) / n
	result := make([][]byte, n)
	for i := uint(0); i < n; i++ {
		result[i] = make([]byte, eachLen)
		copy(result[i], b[i*eachLen:])
	}
	return result
}

func mulAndAddScalars(result ed448.Scalar, values []*gotrax.Keypair, t [][]byte) ed448.Scalar {
	for ix, tn := range t {
		tnv := ed448.NewScalar(tn)
		tnv.Mul(tnv, values[ix].Priv.K())
		result.Add(result, tnv)
	}
	return result
}

// m should be 64 bytes
func generateEcdhProof(wr gotrax.WithRandom, values []*gotrax.Keypair, m []byte, usageID uint8) (*ecdhProof, error) {
	key := gotrax.GenerateKeypair(wr)
	r := key.Priv.K()
	a := key.Pub.K()

	cbuf := gotrax.SerializePoint(a)
	for _, v := range values {
		cbuf = append(cbuf, gotrax.SerializePoint(v.Pub.K())...)
	}
	cbuf = append(cbuf, m...)
	c := gotrax.KdfPrekeyServer(usageID, 64, cbuf)
	p := gotrax.KdfPrekeyServer(usageProofCLambda, uint32(len(values))*lambda, c)
	t := splitBufferIntoN(p, uint(len(values)))

	return &ecdhProof{
		c: c,
		v: mulAndAddScalars(r, values, t),
	}, nil
}

func mulAndAddPoints(values []*gotrax.PublicKey, t [][]byte) ed448.Point {
	curr := ed448.NewPoint([16]uint32{0x00}, [16]uint32{0x01}, [16]uint32{0x01}, [16]uint32{0x00})

	// It would be awesome to have true n-multiexponentiation here, but using PointDoubleScalarMul at least cuts performance roughly in
	// half, so better than nothing
	l := len(values)
	ix := 0
	for ; ix+1 < l; ix += 2 {
		tn1 := ed448.NewScalar(t[ix])
		tn2 := ed448.NewScalar(t[ix+1])
		res := ed448.PointDoubleScalarMul(values[ix].K(), values[ix+1].K(), tn1, tn2)
		curr.Add(curr, res)
	}
	if ix < l {
		tn := ed448.NewScalar(t[ix])
		res := ed448.PointScalarMul(values[ix].K(), tn)
		curr.Add(curr, res)
	}
	return curr
}

func appendPoints(l []byte, values ...*gotrax.PublicKey) []byte {
	for _, v := range values {
		l = append(l, gotrax.SerializePoint(v.K())...)
	}
	return l
}

func (px *ecdhProof) verify(values []*gotrax.PublicKey, m []byte, usageID uint8) bool {
	p := gotrax.KdfPrekeyServer(usageProofCLambda, uint32(len(values))*lambda, px.c)
	t := splitBufferIntoN(p, uint(len(values)))

	a := ed448.PrecomputedScalarMul(px.v)
	a.Sub(a, mulAndAddPoints(values, t))

	c2buf := gotrax.SerializePoint(a)
	c2buf = appendPoints(c2buf, values...)
	c2buf = append(c2buf, m...)
	c2 := gotrax.KdfPrekeyServer(usageID, 64, c2buf)

	return bytes.Equal(px.c, c2)
}

func mulMod(l, r, m *big.Int) *big.Int {
	res := new(big.Int).Mul(l, r)
	res.Mod(res, m)
	return res
}

func mulAndAddValues(r *big.Int, valuesPrivate []*big.Int, t [][]byte) *big.Int {
	for ix, tn := range t {
		tnv := new(big.Int).SetBytes(tn)
		r.Add(r, mulMod(tnv, valuesPrivate[ix], dhQ))
		r.Mod(r, dhQ)
	}
	return r
}

func generateDhProof(wr gotrax.WithRandom, valuesPrivate []*big.Int, valuesPublic []*big.Int, m []byte, usageID uint8) (*dhProof, error) {
	r := generateRandomExponent(dhQ, wr)
	a := new(big.Int).Exp(g3, r, dhP)

	cbuf := gotrax.AppendMPI([]byte{}, a)
	cbuf = gotrax.AppendMPIs(cbuf, valuesPublic...)
	cbuf = append(cbuf, m...)

	c := gotrax.KdfPrekeyServer(usageID, 64, cbuf)
	p := gotrax.KdfPrekeyServer(usageProofCLambda, uint32(len(valuesPrivate))*lambda, c)
	t := splitBufferIntoN(p, uint(len(valuesPrivate)))

	return &dhProof{
		c: c,
		v: mulAndAddValues(r, valuesPrivate, t),
	}, nil

}

func expAndMulValues(values []*big.Int, t [][]byte) *big.Int {
	curr := big.NewInt(1)
	for ix, tn := range t {
		tnv := new(big.Int).SetBytes(tn)
		tnv.Exp(values[ix], tnv, dhP)
		curr = mulMod(curr, tnv, dhP)
	}
	curr.ModInverse(curr, dhP)
	return curr
}

func (px *dhProof) verify(values []*big.Int, m []byte, usageID uint8) bool {
	p := gotrax.KdfPrekeyServer(usageProofCLambda, uint32(len(values))*lambda, px.c)
	t := splitBufferIntoN(p, uint(len(values)))

	a := new(big.Int).Exp(g3, px.v, dhP)
	a = mulMod(a, expAndMulValues(values, t), dhP)

	c2buf := gotrax.AppendMPI([]byte{}, a)
	c2buf = gotrax.AppendMPIs(c2buf, values...)
	c2buf = append(c2buf, m...)
	c2 := gotrax.KdfPrekeyServer(usageID, 64, c2buf)

	return bytes.Equal(px.c, c2)
}
