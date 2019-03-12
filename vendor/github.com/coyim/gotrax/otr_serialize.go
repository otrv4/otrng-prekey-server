package gotrax

import (
	"crypto/dsa"
	"time"
)

// SerializeForSignature generates the parts of the client profile that is used for the signature
func (cp *ClientProfile) SerializeForSignature() []byte {
	out := []byte{}
	fields := uint32(5)

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

	out = AppendShort(out, ClientProfileTagForgingKey)
	out = append(out, cp.ForgingKey.Serialize()...)

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

// Serialize returns the complete serialization of the client profile
func (cp *ClientProfile) Serialize() []byte {
	return append(cp.SerializeForSignature(), cp.Sig.Serialize()...)
}

// SerializeVersions returns the serialization of a versions string
func SerializeVersions(v []byte) []byte {
	return AppendData(nil, v)
}

// SerializeExpiry returns the serialization of the time given as a big-endian unsigned 64-bit number
func SerializeExpiry(t time.Time) []byte {
	val := t.Unix()
	return AppendLong(nil, uint64(val))
}

// SerializeDSAKey will serialize the four component types of the DSA key, prefixed with the key type
func SerializeDSAKey(k *dsa.PublicKey) []byte {
	result := DsaKeyType
	result = AppendMPI(result, k.P)
	result = AppendMPI(result, k.Q)
	result = AppendMPI(result, k.G)
	result = AppendMPI(result, k.Y)
	return result
}

// DeserializeDSAKey tries to deserialize the data or returns failure
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

// DeserializeField tries to deserialize one client profile field or returns failure
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
	case ClientProfileTagForgingKey:
		cp.ForgingKey = &PublicKey{keyType: ForgingKey}
		if buf, ok = cp.ForgingKey.Deserialize(buf); !ok {
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

// Deserialize will try to deserialize as a client profile or return failure
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

// SerializeForSignature serializes the parts of the prekey profile to be signed
func (pp *PrekeyProfile) SerializeForSignature() []byte {
	var out []byte
	out = AppendWord(out, pp.InstanceTag)
	out = append(out, SerializeExpiry(pp.Expiration)...)
	out = append(out, pp.SharedPrekey.Serialize()...)
	return out
}

// Serialize willl return the serialized form of the prekey profile
func (pp *PrekeyProfile) Serialize() []byte {
	return append(pp.SerializeForSignature(), pp.Sig.Serialize()...)
}

// Deserialize will try to deserialize as a prekey profile or return failure
func (pp *PrekeyProfile) Deserialize(buf []byte) ([]byte, bool) {
	var ok bool

	if buf, pp.InstanceTag, ok = ExtractWord(buf); !ok {
		return nil, false
	}

	if buf, pp.Expiration, ok = ExtractTime(buf); !ok {
		return nil, false
	}

	pp.SharedPrekey = CreatePublicKey(nil, SharedPrekeyKey)
	if buf, ok = pp.SharedPrekey.Deserialize(buf); !ok {
		return nil, false
	}

	pp.Sig = &EddsaSignature{}
	if buf, ok = pp.Sig.Deserialize(buf); !ok {
		return nil, false
	}

	return buf, true
}

// Serialize will return the serialized form of the prekey message
func (pm *PrekeyMessage) Serialize() []byte {
	out := AppendShort(nil, version)
	out = append(out, messageTypePrekeyMessage)
	out = AppendWord(out, pm.Identifier)
	out = AppendWord(out, pm.InstanceTag)
	out = append(out, SerializePoint(pm.Y)...)
	out = AppendMPI(out, pm.B)
	return out
}

// Deserialize will try to deserialize as a prekey message or return failure
func (pm *PrekeyMessage) Deserialize(buf []byte) ([]byte, bool) {
	var ok1 bool
	var v uint16

	if buf, v, ok1 = ExtractShort(buf); !ok1 || v != version { // version
		return nil, false
	}

	if len(buf) < 1 || buf[0] != messageTypePrekeyMessage {
		return nil, false
	}
	buf = buf[1:] // message type

	if buf, pm.Identifier, ok1 = ExtractWord(buf); !ok1 {
		return nil, false
	}

	if buf, pm.InstanceTag, ok1 = ExtractWord(buf); !ok1 {
		return nil, false
	}

	if buf, pm.Y, ok1 = DeserializePoint(buf); !ok1 {
		return nil, false
	}

	if buf, pm.B, ok1 = ExtractMPI(buf); !ok1 {
		return nil, false
	}

	return buf, true
}
