package gotrax

import "github.com/otrv4/ed448"

// Serialize returns a serialization of the given public key
func (p *PublicKey) Serialize() []byte {
	keyType := []byte{0xBA, 0xD0}
	switch p.keyType {
	case Ed448Key:
		keyType = Ed448KeyType
	case SharedPrekeyKey:
		keyType = SharedPrekeyKeyType
	case ForgingKey:
		keyType = ForgingKeyType
	}
	return append(keyType, p.k.DSAEncode()...)
}

// Serialize returns a serialization of the given signature
func (s *EddsaSignature) Serialize() []byte {
	return s.s[:]
}

// Deserialize tries to deserialize the given bytes into a signature or signals failure
func (s *EddsaSignature) Deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	var res []byte
	if buf, res, ok = ExtractFixedData(buf, 114); !ok {
		return nil, false
	}
	copy(s.s[:], res)
	return buf, true
}

// SerializePoint will return the DSA encoding of the ECC point public key
func SerializePoint(p ed448.Point) []byte {
	return p.DSAEncode()
}

// DeserializePoint tries to deserialize the buffer into an ECC public key
func DeserializePoint(buf []byte) ([]byte, ed448.Point, bool) {
	if len(buf) < 57 {
		return buf, nil, false
	}
	tp := ed448.NewPointFromBytes([]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})
	tp.DSADecode(buf[0:57])
	return buf[57:], tp, true
}

// SerializeScalar returns the byte level representation of the ECC scalar
func SerializeScalar(s ed448.Scalar) []byte {
	return s.Encode()
}

// DeserializeScalar tries to interpret the bytes given as an ECC scalar, or signals failure
func DeserializeScalar(buf []byte) ([]byte, ed448.Scalar, bool) {
	if len(buf) < 56 {
		return nil, nil, false
	}
	ts := ed448.NewScalar()
	ts.Decode(buf[0:56])
	return buf[56:], ts, true

}

// Deserialize tries to interpret the bytes given as an OTR public key, or signals failure
func (p *PublicKey) Deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	pubKeyType := uint16(0)

	if buf, pubKeyType, ok = ExtractShort(buf); !ok {
		return nil, false
	}

	keyType := uint16(0xBAD0)
	switch p.keyType {
	case Ed448Key:
		keyType = Ed448KeyTypeInt
	case SharedPrekeyKey:
		keyType = SharedPrekeyKeyTypeInt
	case ForgingKey:
		keyType = ForgingKeyTypeInt
	}

	if pubKeyType != keyType {
		return nil, false
	}

	buf, p.k, ok = DeserializePoint(buf)
	return buf, ok
}
