package prekeyserver

import "encoding/base64"

func decodeMessage(inp string) ([]byte, bool) {
	decoded, err := base64.StdEncoding.DecodeString(inp)
	if err != nil {
		return nil, false
	}
	return decoded, true
}

func encodeMessage(inp []byte) string {
	return base64.StdEncoding.EncodeToString(inp)
}
