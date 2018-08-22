package gotrax

import "github.com/otrv4/ed448"

func (p *PublicKey) Serialize() []byte {
	keyType := []byte{0xBA, 0xD0}
	switch p.keyType {
	case Ed448Key:
		keyType = Ed448KeyType
	case SharedPrekeyKey:
		keyType = SharedPrekeyKeyType
	}
	return append(keyType, p.k.DSAEncode()...)
}

func (s *EddsaSignature) Serialize() []byte {
	return s.s[:]
}

func (s *EddsaSignature) Deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	var res []byte
	if buf, res, ok = ExtractFixedData(buf, 114); !ok {
		return nil, false
	}
	copy(s.s[:], res)
	return buf, true
}

func SerializePoint(p ed448.Point) []byte {
	return p.DSAEncode()
}

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

func SerializeScalar(s ed448.Scalar) []byte {
	return s.Encode()
}

func DeserializeScalar(buf []byte) ([]byte, ed448.Scalar, bool) {
	if len(buf) < 56 {
		return nil, nil, false
	}
	ts := ed448.NewScalar()
	ts.Decode(buf[0:56])
	return buf[56:], ts, true

}

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
	}

	if pubKeyType != keyType {
		return nil, false
	}

	buf, p.k, ok = DeserializePoint(buf)
	return buf, ok
}
