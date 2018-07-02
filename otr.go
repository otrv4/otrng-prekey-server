package prekeyserver

import (
	"time"
)

type clientProfile struct {
	identifier            uint32
	instanceTag           uint32
	publicKey             *publicKey
	versions              []byte
	expiration            time.Time
	dsaKey                []byte
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

const (
	clientProfileTagIdentifier  = uint16(0x0001)
	clientProfileTagInstanceTag = uint16(0x0002)
	clientProfileTagPublicKey   = uint16(0x0003)
	clientProfileTagVersions    = uint16(0x0005)
	clientProfileTagExpiry      = uint16(0x0006)
)

func (cp *clientProfile) serialize() []byte {
	out := []byte{}
	fields := uint32(5)

	// TODO: serialize DSA stuff as well
	// if cp.dsaKey != nil {
	// 	fields++
	// }
	// if cp.transitionalSignature != nil {
	// 	fields++
	// }

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

	out = append(out, cp.sig.serialize()...)

	return out
}

func (cp *clientProfile) deserializeField(buf []byte) ([]byte, bool) {
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
	}
	return buf, true
}

func (cp *clientProfile) deserialize(buf []byte) ([]byte, bool) {
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
	// TODO: implement
	panic("implement me")
	return nil
}

func (pp *prekeyProfile) deserialize(buf []byte) ([]byte, bool) {
	// TODO: implement
	panic("implement me")
	return nil, false
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
	// TODO: implement
	panic("implement me")
	return nil
}

func (pe *prekeyEnsemble) deserialize(buf []byte) ([]byte, bool) {
	// TODO: implement
	panic("implement me")
	return nil, false
}
