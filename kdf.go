package prekeyserver

import "golang.org/x/crypto/sha3"

func kdfx(usageID uint8, size uint16, values ...[]byte) []byte {
	buf := make([]byte, size)
	kdf(usageID, buf, values...)
	return buf
}

func kdfx_otrv4(usageID uint8, size uint16, values ...[]byte) []byte {
	buf := make([]byte, size)
	kdf_otrv4(usageID, buf, values...)
	return buf
}

func kdf(usageID uint8, buf []byte, values ...[]byte) {
	sha3.ShakeSum256(buf, append(append([]byte("OTR-Prekey-Server"), usageID), concat(values...)...))
}

func kdf_otrv4(usageID uint8, buf []byte, values ...[]byte) {
	sha3.ShakeSum256(buf, append(append([]byte("OTRv4"), usageID), concat(values...)...))
}

func concat(values ...[]byte) []byte {
	result := []byte{}
	for _, v := range values {
		result = append(result, v...)
	}
	return result
}
