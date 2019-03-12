package gotrax

import "golang.org/x/crypto/sha3"

// KdfFunc is a function that can be used as a key derivation function
type KdfFunc func(uint8, uint32, ...[]byte) []byte

// KdfPrekeyServer will apply a KDF with parameters for the OTR prekey server
func KdfPrekeyServer(usageID uint8, size uint32, values ...[]byte) []byte {
	buf := make([]byte, size)
	KdfxPrekeyServer(usageID, buf, values...)
	return buf
}

// KdfxPrekeyServer will apply a KDF with parameters for the OTR prekey server
func KdfxPrekeyServer(usageID uint8, buf []byte, values ...[]byte) {
	sha3.ShakeSum256(buf, append(append(kdfPrekeyServerPrefix, usageID), concat(values...)...))
}

// Kdf will apply a KDF with parameters for the OTR client
func Kdf(usageID uint8, size uint32, values ...[]byte) []byte {
	buf := make([]byte, size)
	Kdfx(usageID, buf, values...)
	return buf
}

// Kdfx will apply a KDF with parameters for the OTR client
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
