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

const lambda = uint32(352)

func bufferIsZero(b []byte) bool {
	for _, v := range b {
		if v != byte(0x00) {
			return false
		}
	}
	return true
}

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

func generateRandomGroupValue(len uint, wr gotrax.WithRandom) []byte {
	b := make([]byte, len)

	for {
		gotrax.RandomInto(wr, b)
		if !bufferIsZero(b) {
			return b
		}
	}

	return nil
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

// m should be 64 bytes
func generateEcdhProof(wr gotrax.WithRandom, values []*gotrax.Keypair, m []byte, usageID uint8) (*ecdhProof, error) {
	rbuf := generateRandomGroupValue(56, wr)
	r := ed448.NewScalar(rbuf)
	a := ed448.PrecomputedScalarMul(r)

	cbuf := gotrax.SerializePoint(a)
	for _, v := range values {
		cbuf = append(cbuf, gotrax.SerializePoint(v.Pub.K())...)
	}
	cbuf = append(cbuf, m...)
	c := gotrax.KdfPrekeyServer(usageID, 64, cbuf)
	p := gotrax.KdfPrekeyServer(usageProofCLambda, uint32(len(values))*lambda, c)
	t := splitBufferIntoN(p, uint(len(values)))
	result := r.Copy()
	for ix, tn := range t {
		tnv := ed448.NewScalar(tn)
		tnv.Mul(tnv, values[ix].Priv.K())
		result.Add(result, tnv)
	}

	return &ecdhProof{
		c: c,
		v: result,
	}, nil
}

func (px *ecdhProof) verify(values []*gotrax.PublicKey, m []byte, usageID uint8) bool {
	p := gotrax.KdfPrekeyServer(usageProofCLambda, uint32(len(values))*lambda, px.c)
	t := splitBufferIntoN(p, uint(len(values)))
	a := ed448.PrecomputedScalarMul(px.v)
	var curr ed448.Point
	// TODO: we should be able to do PointDoubleScalarMul here instead
	// in order to improve performance significantly
	for ix, tn := range t {
		tnv := ed448.NewScalar(tn)
		res := ed448.PointScalarMul(values[ix].K(), tnv)
		if curr == nil {
			curr = res
		} else {
			curr.Add(curr, res)
		}
	}
	// TODO: subtract instead of this thing
	a.Add(a, ed448.PointScalarMul(curr, scalarMinusOne))

	c2buf := gotrax.SerializePoint(a)
	for _, v := range values {
		c2buf = append(c2buf, gotrax.SerializePoint(v.K())...)
	}
	c2buf = append(c2buf, m...)
	c2 := gotrax.KdfPrekeyServer(usageID, 64, c2buf)

	return bytes.Equal(px.c, c2)
}

func mul(l, r *big.Int) *big.Int {
	return new(big.Int).Mul(l, r)
}

func mulMod(l, r, m *big.Int) *big.Int {
	res := mul(l, r)
	res.Mod(res, m)
	return res
}

func generateDhProof(wr gotrax.WithRandom, valuesPrivate []*big.Int, valuesPublic []*big.Int, m []byte, usageID uint8) (*dhProof, error) {
	r := generateRandomExponent(dhQ, wr)
	a := new(big.Int).Exp(g3, r, dhP)

	cbuf := gotrax.AppendMPI([]byte{}, a)
	for _, v := range valuesPublic {
		cbuf = gotrax.AppendMPI(cbuf, v)
	}
	cbuf = append(cbuf, m...)
	c := gotrax.KdfPrekeyServer(usageID, 64, cbuf)
	p := gotrax.KdfPrekeyServer(usageProofCLambda, uint32(len(valuesPrivate))*lambda, c)
	t := splitBufferIntoN(p, uint(len(valuesPrivate)))

	result := new(big.Int).Set(r)
	for ix, tn := range t {
		tnv := new(big.Int).SetBytes(tn)
		result.Add(result, mulMod(tnv, valuesPrivate[ix], dhQ))
		result.Mod(result, dhQ)
	}

	result.Mod(result, dhQ)
	return &dhProof{
		c: c,
		v: result,
	}, nil

}

func (px *dhProof) verify(values []*big.Int, m []byte, usageID uint8) bool {
	p := gotrax.KdfPrekeyServer(usageProofCLambda, uint32(len(values))*lambda, px.c)
	t := splitBufferIntoN(p, uint(len(values)))

	curr := big.NewInt(1)
	for ix, tn := range t {
		tnv := new(big.Int).SetBytes(tn)
		tnv.Exp(values[ix], tnv, dhP)
		curr = mulMod(curr, tnv, dhP)
	}

	a := new(big.Int).Exp(g3, px.v, dhP)
	curr.ModInverse(curr, dhP)
	a = mulMod(a, curr, dhP)

	c2buf := gotrax.AppendMPI([]byte{}, a)
	for _, v := range values {
		c2buf = gotrax.AppendMPI(c2buf, v)
	}
	c2buf = append(c2buf, m...)
	c2 := gotrax.KdfPrekeyServer(usageID, 64, c2buf)

	return bytes.Equal(px.c, c2)
}
