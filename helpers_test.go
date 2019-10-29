package prekeyserver

import (
	"math/big"

	"github.com/otrv4/ed448"
	"github.com/otrv4/gotrx"
)

// bnFromHex is a test utility that doesn't take into account possible errors. Thus, make sure to only call it with valid hexadecimal strings (of even length)
func bnFromHex(s string) *big.Int {
	res, _ := new(big.Int).SetString(s, 16)
	return res
}

func generatePointFrom(data [symKeyLength]byte) ed448.Point {
	return generatePublicKeyFrom(data).K()
}

func generatePublicKeyFrom(data [symKeyLength]byte) *gotrx.PublicKey {
	return gotrx.DeriveKeypair(data).Pub
}

func generateScalarFrom(data ...byte) ed448.Scalar {
	v := [privKeyLength]byte{}
	copy(v[:], data[:])
	return ed448.NewScalar(v[:])
}
