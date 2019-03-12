package gotrax

import (
	"math/big"

	"github.com/otrv4/ed448"
)

func generatePointFrom(data [SymKeyLength]byte) ed448.Point {
	return generatePublicKeyFrom(data).k
}

func generatePublicKeyFrom(data [SymKeyLength]byte) *PublicKey {
	return DeriveKeypair(data).Pub
}

func generateScalarFrom(data ...byte) ed448.Scalar {
	v := [PrivKeyLength]byte{}
	copy(v[:], data[:])
	return ed448.NewScalar(v[:])
}

func bnFromHex(s string) *big.Int {
	res, _ := new(big.Int).SetString(s, 16)
	return res
}
