package prekeyserver

import (
	"crypto/dsa"
	"time"
)

type clientProfile struct {
	identifier            uint32
	instanceTag           uint32
	publicKey             *publicKey
	versions              []byte
	expiration            time.Time
	dsaKey                *dsa.PublicKey
	transitionalSignature []byte
	sig                   *eddsaSignature
}

type prekeyProfile struct {
	identifier   uint32
	instanceTag  uint32
	expiration   time.Time
	sharedPrekey *publicKey
	sig          *eddsaSignature
}

type prekeyMessage struct {
	identifier  uint32
	instanceTag uint32
	y           *publicKey
	b           []byte
}

type prekeyEnsemble struct {
	cp *clientProfile
	pp *prekeyProfile
	pm *prekeyMessage
}

func serializeVersions(v []byte) []byte {
	return appendData(nil, v)
}

func serializeExpiry(t time.Time) []byte {
	val := t.Unix()
	return appendLong(nil, uint64(val))
}

var dsaKeyType = []byte{0x00, 0x00}

func serializeDSAKey(k *dsa.PublicKey) []byte {
	result := dsaKeyType
	result = appendMPI(result, k.P)
	result = appendMPI(result, k.Q)
	result = appendMPI(result, k.G)
	result = appendMPI(result, k.Y)
	return result
}

func deserializeDSAKey(buf []byte) ([]byte, *dsa.PublicKey, bool) {
	res := &dsa.PublicKey{}
	var ok bool
	var keyType uint16
	if buf, keyType, ok = extractShort(buf); !ok || keyType != uint16(0x0000) { // key type
		return nil, nil, false
	}

	if buf, res.P, ok = extractMPI(buf); !ok {
		return nil, nil, false
	}

	if buf, res.Q, ok = extractMPI(buf); !ok {
		return nil, nil, false
	}

	if buf, res.G, ok = extractMPI(buf); !ok {
		return nil, nil, false
	}

	if buf, res.Y, ok = extractMPI(buf); !ok {
		return nil, nil, false
	}

	return buf, res, true
}

const (
	clientProfileTagIdentifier            = uint16(0x0001)
	clientProfileTagInstanceTag           = uint16(0x0002)
	clientProfileTagPublicKey             = uint16(0x0003)
	clientProfileTagVersions              = uint16(0x0005)
	clientProfileTagExpiry                = uint16(0x0006)
	clientProfileTagDSAKey                = uint16(0x0007)
	clientProfileTagTransitionalSignature = uint16(0x0008)
)

func (cp *clientProfile) serialize() []byte {
	out := []byte{}
	fields := uint32(5)

	if cp.dsaKey != nil {
		fields++
	}

	if cp.transitionalSignature != nil {
		fields++
	}

	out = appendWord(out, fields)

	out = appendShort(out, clientProfileTagIdentifier)
	out = appendWord(out, cp.identifier)

	out = appendShort(out, clientProfileTagInstanceTag)
	out = appendWord(out, cp.instanceTag)

	out = appendShort(out, clientProfileTagPublicKey)
	out = append(out, cp.publicKey.serialize()...)

	out = appendShort(out, clientProfileTagVersions)
	out = append(out, serializeVersions(cp.versions)...)

	out = appendShort(out, clientProfileTagExpiry)
	out = append(out, serializeExpiry(cp.expiration)...)

	if cp.dsaKey != nil {
		out = appendShort(out, clientProfileTagDSAKey)
		out = append(out, serializeDSAKey(cp.dsaKey)...)
	}

	if cp.transitionalSignature != nil {
		out = appendShort(out, clientProfileTagTransitionalSignature)
		out = append(out, cp.transitionalSignature...)
	}

	out = append(out, cp.sig.serialize()...)

	return out
}

func (cp *clientProfile) deserializeField(buf []byte) ([]byte, bool) {
	var tp uint16
	var ok bool

	if buf, tp, ok = extractShort(buf); !ok {
		return nil, false
	}

	switch tp {
	case uint16(1):
		if buf, cp.identifier, ok = extractWord(buf); !ok {
			return nil, false
		}
	case uint16(2):
		if buf, cp.instanceTag, ok = extractWord(buf); !ok {
			return nil, false
		}
	case uint16(3):
		cp.publicKey = &publicKey{}
		if buf, ok = cp.publicKey.deserialize(buf); !ok {
			return nil, false
		}
	case uint16(5):
		if buf, cp.versions, ok = extractData(buf); !ok {
			return nil, false
		}
	case uint16(6):
		if buf, cp.expiration, ok = extractTime(buf); !ok {
			return nil, false
		}
	case uint16(7):
		if buf, cp.dsaKey, ok = deserializeDSAKey(buf); !ok {
			return nil, false
		}
	case uint16(8):
		if buf, cp.transitionalSignature, ok = extractFixedData(buf, 40); !ok {
			return nil, false
		}
	default:
		return nil, false
	}
	return buf, true
}

func (cp *clientProfile) deserialize(buf []byte) ([]byte, bool) {
	var fields uint32
	var ok bool
	if buf, fields, ok = extractWord(buf); !ok {
		return nil, false
	}

	for i := uint32(0); i < fields; i++ {
		if buf, ok = cp.deserializeField(buf); !ok {
			return nil, false
		}
	}

	cp.sig = &eddsaSignature{}
	if buf, ok = cp.sig.deserialize(buf); !ok {
		return nil, false
	}

	return buf, true
}

func (pp *prekeyProfile) serialize() []byte {
	var out []byte
	out = appendWord(out, pp.identifier)
	out = appendWord(out, pp.instanceTag)
	out = append(out, serializeExpiry(pp.expiration)...)
	out = append(out, pp.sharedPrekey.serialize()...)
	out = append(out, pp.sig.serialize()...)

	return out
}

func (pp *prekeyProfile) deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	if buf, pp.identifier, ok = extractWord(buf); !ok {
		return nil, false
	}

	if buf, pp.instanceTag, ok = extractWord(buf); !ok {
		return nil, false
	}

	if buf, pp.expiration, ok = extractTime(buf); !ok {
		return nil, false
	}

	pp.sharedPrekey = &publicKey{}
	if buf, ok = pp.sharedPrekey.deserialize(buf); !ok {
		return nil, false
	}

	pp.sig = &eddsaSignature{}
	if buf, ok = pp.sig.deserialize(buf); !ok {
		return nil, false
	}

	return buf, true
}

func (pm *prekeyMessage) serialize() []byte {
	out := appendShort(nil, version)
	out = append(out, messageTypePrekeyMessage)
	out = appendWord(out, pm.identifier)
	out = appendWord(out, pm.instanceTag)
	out = append(out, pm.y.serialize()...)
	out = appendData(out, pm.b)
	return out
}

func (pm *prekeyMessage) deserialize(buf []byte) ([]byte, bool) {
	var ok1 bool
	var v uint16

	if buf, v, ok1 = extractShort(buf); !ok1 || v != version { // version
		return nil, false
	}

	if len(buf) < 1 || buf[0] != messageTypePrekeyMessage {
		return nil, false
	}
	buf = buf[1:] // message type

	if buf, pm.identifier, ok1 = extractWord(buf); !ok1 {
		return nil, false
	}

	if buf, pm.instanceTag, ok1 = extractWord(buf); !ok1 {
		return nil, false
	}

	y := &publicKey{}
	if buf, ok1 = y.deserialize(buf); !ok1 {
		return nil, false
	}
	pm.y = y

	if buf, pm.b, ok1 = extractData(buf); !ok1 {
		return nil, false
	}

	return buf, true
}

func (pe *prekeyEnsemble) serialize() []byte {
	var out []byte
	out = append(out, pe.cp.serialize()...)
	out = append(out, pe.pp.serialize()...)
	out = append(out, pe.pm.serialize()...)
	return out
}

func (pe *prekeyEnsemble) deserialize(buf []byte) ([]byte, bool) {
	var ok bool

	pe.cp = &clientProfile{}
	if buf, ok = pe.cp.deserialize(buf); !ok {
		return nil, false
	}

	pe.pp = &prekeyProfile{}
	if buf, ok = pe.pp.deserialize(buf); !ok {
		return nil, false
	}

	pe.pm = &prekeyMessage{}
	if buf, ok = pe.pm.deserialize(buf); !ok {
		return nil, false
	}

	return buf, true
}
