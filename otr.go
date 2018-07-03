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
	// TODO: check deserialization
	res := &dsa.PublicKey{}
	buf, _, _ = extractShort(buf) // key type
	buf, res.P, _ = extractMPI(buf)
	buf, res.Q, _ = extractMPI(buf)
	buf, res.G, _ = extractMPI(buf)
	buf, res.Y, _ = extractMPI(buf)
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
	// TODO: check deserialization
	var tp uint16
	buf, tp, _ = extractShort(buf)
	switch tp {
	case uint16(1):
		buf, cp.identifier, _ = extractWord(buf)
	case uint16(2):
		buf, cp.instanceTag, _ = extractWord(buf)
	case uint16(3):
		cp.publicKey = &publicKey{}
		buf, _ = cp.publicKey.deserialize(buf)
	case uint16(5):
		buf, cp.versions, _ = extractData(buf)
	case uint16(6):
		buf, cp.expiration, _ = extractTime(buf)
	case uint16(7):
		buf, cp.dsaKey, _ = deserializeDSAKey(buf)
	case uint16(8):
		buf, cp.transitionalSignature, _ = extractFixedData(buf, 40)
	}
	return buf, true
}

func (cp *clientProfile) deserialize(buf []byte) ([]byte, bool) {
	// TODO: check deserialization
	var fields uint32
	buf, fields, _ = extractWord(buf)
	for i := uint32(0); i < fields; i++ {
		buf, _ = cp.deserializeField(buf)
	}

	cp.sig = &eddsaSignature{}
	buf, _ = cp.sig.deserialize(buf)

	return buf, true
}

func (pp *prekeyProfile) serialize() []byte {
	var out []byte
	// out := appendShort(nil, version)
	// out = append(out, messageTypePrekeyProfile)
	out = appendWord(out, pp.identifier)
	out = appendWord(out, pp.instanceTag)
	out = append(out, serializeExpiry(pp.expiration)...)
	out = append(out, pp.sharedPrekey.serialize()...)
	out = append(out, pp.sig.serialize()...)

	return out
}

func (pp *prekeyProfile) deserialize(buf []byte) ([]byte, bool) {
	// TODO: check deserialization
	//	buf, _, _ = extractShort(buf) // version
	//	buf = buf[1:]                 // message type

	buf, pp.identifier, _ = extractWord(buf)
	buf, pp.instanceTag, _ = extractWord(buf)
	buf, pp.expiration, _ = extractTime(buf)
	pp.sharedPrekey = &publicKey{}
	buf, _ = pp.sharedPrekey.deserialize(buf)
	pp.sig = &eddsaSignature{}
	buf, _ = pp.sig.deserialize(buf)

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
	// TODO: check deserialization
	buf, _, _ = extractShort(buf) // version
	buf = buf[1:]                 // message type

	buf, pm.identifier, _ = extractWord(buf)
	buf, pm.instanceTag, _ = extractWord(buf)
	pm.y = &publicKey{}
	buf, _ = pm.y.deserialize(buf)
	buf, pm.b, _ = extractData(buf)

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
	// TODO: check deserialization
	pe.cp = &clientProfile{}
	buf, _ = pe.cp.deserialize(buf)

	pe.pp = &prekeyProfile{}
	buf, _ = pe.pp.deserialize(buf)

	pe.pm = &prekeyMessage{}
	buf, _ = pe.pm.deserialize(buf)

	return buf, true
}
