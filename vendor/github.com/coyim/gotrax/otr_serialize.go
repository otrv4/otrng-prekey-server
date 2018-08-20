package gotrax

import (
	"crypto/dsa"
	"time"
)

func (cp *ClientProfile) SerializeForSignature() []byte {
	out := []byte{}
	fields := uint32(4)

	if cp.DsaKey != nil {
		fields++
	}

	if cp.TransitionalSignature != nil {
		fields++
	}

	out = AppendWord(out, fields)

	out = AppendShort(out, ClientProfileTagInstanceTag)
	out = AppendWord(out, cp.InstanceTag)

	out = AppendShort(out, ClientProfileTagPublicKey)
	out = append(out, cp.PublicKey.Serialize()...)

	out = AppendShort(out, ClientProfileTagVersions)
	out = append(out, SerializeVersions(cp.Versions)...)

	out = AppendShort(out, ClientProfileTagExpiry)
	out = append(out, SerializeExpiry(cp.Expiration)...)

	if cp.DsaKey != nil {
		out = AppendShort(out, ClientProfileTagDSAKey)
		out = append(out, SerializeDSAKey(cp.DsaKey)...)
	}

	if cp.TransitionalSignature != nil {
		out = AppendShort(out, ClientProfileTagTransitionalSignature)
		out = append(out, cp.TransitionalSignature...)
	}

	return out
}

func (cp *ClientProfile) Serialize() []byte {
	return append(cp.SerializeForSignature(), cp.Sig.Serialize()...)
}

func SerializeVersions(v []byte) []byte {
	return AppendData(nil, v)
}

func SerializeExpiry(t time.Time) []byte {
	val := t.Unix()
	return AppendLong(nil, uint64(val))
}

func SerializeDSAKey(k *dsa.PublicKey) []byte {
	result := DsaKeyType
	result = AppendMPI(result, k.P)
	result = AppendMPI(result, k.Q)
	result = AppendMPI(result, k.G)
	result = AppendMPI(result, k.Y)
	return result
}

func DeserializeDSAKey(buf []byte) ([]byte, *dsa.PublicKey, bool) {
	res := &dsa.PublicKey{}
	var ok bool
	var keyType uint16
	if buf, keyType, ok = ExtractShort(buf); !ok || keyType != uint16(0x0000) { // key type
		return nil, nil, false
	}

	if buf, res.P, ok = ExtractMPI(buf); !ok {
		return nil, nil, false
	}

	if buf, res.Q, ok = ExtractMPI(buf); !ok {
		return nil, nil, false
	}

	if buf, res.G, ok = ExtractMPI(buf); !ok {
		return nil, nil, false
	}

	if buf, res.Y, ok = ExtractMPI(buf); !ok {
		return nil, nil, false
	}

	return buf, res, true
}

func (cp *ClientProfile) DeserializeField(buf []byte) ([]byte, bool) {
	var tp uint16
	var ok bool

	if buf, tp, ok = ExtractShort(buf); !ok {
		return nil, false
	}

	switch tp {
	case ClientProfileTagInstanceTag:
		if buf, cp.InstanceTag, ok = ExtractWord(buf); !ok {
			return nil, false
		}
	case ClientProfileTagPublicKey:
		cp.PublicKey = &PublicKey{keyType: Ed448Key}
		if buf, ok = cp.PublicKey.Deserialize(buf); !ok {
			return nil, false
		}
	case ClientProfileTagVersions:
		if buf, cp.Versions, ok = ExtractData(buf); !ok {
			return nil, false
		}
	case ClientProfileTagExpiry:
		if buf, cp.Expiration, ok = ExtractTime(buf); !ok {
			return nil, false
		}
	case ClientProfileTagDSAKey:
		if buf, cp.DsaKey, ok = DeserializeDSAKey(buf); !ok {
			return nil, false
		}
	case ClientProfileTagTransitionalSignature:
		if buf, cp.TransitionalSignature, ok = ExtractFixedData(buf, 40); !ok {
			return nil, false
		}
	default:
		return nil, false
	}
	return buf, true
}

func (cp *ClientProfile) Deserialize(buf []byte) ([]byte, bool) {
	var fields uint32
	var ok bool
	if buf, fields, ok = ExtractWord(buf); !ok {
		return nil, false
	}

	for i := uint32(0); i < fields; i++ {
		if buf, ok = cp.DeserializeField(buf); !ok {
			return nil, false
		}
	}

	cp.Sig = &EddsaSignature{}
	if buf, ok = cp.Sig.Deserialize(buf); !ok {
		return nil, false
	}

	return buf, true
}
