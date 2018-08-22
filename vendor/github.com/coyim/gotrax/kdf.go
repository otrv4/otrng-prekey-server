package gotrax

import "golang.org/x/crypto/sha3"

type KdfFunc func(uint8, uint16, ...[]byte) []byte

func KdfPrekeyServer(usageID uint8, size uint16, values ...[]byte) []byte {
	buf := make([]byte, size)
	KdfxPrekeyServer(usageID, buf, values...)
	return buf
}

func KdfxPrekeyServer(usageID uint8, buf []byte, values ...[]byte) {
	sha3.ShakeSum256(buf, append(append(kdfPrekeyServerPrefix, usageID), concat(values...)...))
}

func Kdf(usageID uint8, size uint16, values ...[]byte) []byte {
	buf := make([]byte, size)
	Kdfx(usageID, buf, values...)
	return buf
}

func Kdfx(usageID uint8, buf []byte, values ...[]byte) {
	sha3.ShakeSum256(buf, append(append(kdfPrefix, usageID), concat(values...)...))
}

func concat(values ...[]byte) []byte {
	result := []byte{}
	for _, v := range values {
		result = append(result, v...)
	}
	return result
}
