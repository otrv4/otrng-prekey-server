package prekeyserver

import (
	"math/big"

	"github.com/otrv4/ed448"
)

// bnFromHex is a test utility that doesn't take into account possible errors. Thus, make sure to only call it with valid hexadecimal strings (of even length)
func bnFromHex(s string) *big.Int {
	res, _ := new(big.Int).SetString(s, 16)
	return res
}

func generatePointFrom(data [symKeyLength]byte) ed448.Point {
	return generatePublicKeyFrom(data).k
}

func generatePublicKeyFrom(data [symKeyLength]byte) *publicKey {
	return deriveKeypair(data).pub
}

func generateScalarFrom(data ...byte) ed448.Scalar {
	v := [privKeyLength]byte{}
	copy(v[:], data[:])
	return ed448.NewScalar(v[:])
}
