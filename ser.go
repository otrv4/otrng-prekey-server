package prekeyserver

import (
	"crypto/dsa"
	"time"

	"github.com/twstrike/ed448"
)

type serializable interface {
	deserialize([]byte) ([]byte, bool)
	serialize() []byte
}

func (m *dake1Message) deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	buf, v, ok := extractShort(buf)
	if !ok || v != version {
		return buf, false
	}

	if len(buf) < 1 || buf[0] != dake1MessageType {
		return buf, false
	}
	buf = buf[1:]

	buf, m.instanceTag, ok = extractWord(buf)
	if !ok {
		return buf, false
	}

	m.clientProfile = &clientProfile{}
	buf, ok = m.clientProfile.deserialize(buf)
	if !ok {
		return buf, false
	}

	buf, m.i, ok = deserializePoint(buf)
	if !ok {
		return buf, false
	}

	return buf, true
}

func (m *dake1Message) serialize() []byte {
	out := appendShort(nil, version)
	out = append(out, dake1MessageType)
	out = appendWord(out, m.instanceTag)
	out = append(out, m.clientProfile.serialize()...)
	out = append(out, serializePoint(m.i)...)
	return out
}

func (m *dake2Message) serialize() []byte {
	out := appendShort(nil, version)
	out = append(out, dake2MessageType)
	out = appendWord(out, m.instanceTag)
	out = appendData(out, m.serverIdentity)
	out = appendData(out, m.serverFingerprint[:])
	out = append(out, serializePoint(m.s)...)
	out = append(out, m.sigma.serialize()...)
	return out
}

func (m *dake2Message) deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	buf, v, ok := extractShort(buf)
	if !ok || v != version {
		return buf, false
	}

	if len(buf) < 1 || buf[0] != dake2MessageType {
		return buf, false
	}
	buf = buf[1:]

	if buf, m.instanceTag, ok = extractWord(buf); !ok {
		return nil, false
	}

	if buf, m.serverIdentity, ok = extractData(buf); !ok {
		return nil, false
	}

	var tmp []byte
	if buf, tmp, ok = extractData(buf); !ok {
		return nil, false
	}
	copy(m.serverFingerprint[:], tmp)

	if buf, m.s, ok = deserializePoint(buf); !ok {
		return nil, false
	}

	m.sigma = &ringSignature{}
	if buf, ok = m.sigma.deserialize(buf); !ok {
		return nil, false
	}

	return buf, true
}

func (m *dake3Message) serialize() []byte {
	out := appendShort(nil, version)
	out = append(out, dake3MessageType)
	out = appendWord(out, m.instanceTag)
	out = append(out, m.sigma.serialize()...)
	out = appendData(out, m.message)
	return out
}

func (m *dake3Message) deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	buf, v, ok := extractShort(buf)
	if !ok || v != version {
		return buf, false
	}

	if len(buf) < 1 || buf[0] != dake3MessageType {
		return buf, false
	}
	buf = buf[1:]

	if buf, m.instanceTag, ok = extractWord(buf); !ok {
		return nil, false
	}

	m.sigma = &ringSignature{}
	if buf, ok = m.sigma.deserialize(buf); !ok {
		return nil, false
	}

	if buf, m.message, ok = extractData(buf); !ok {
		return nil, false
	}

	return buf, true
}

func (m *publicationMessage) serialize() []byte {
	out := appendShort(nil, version)
	out = append(out, messageTypePublication)
	out = append(out, uint8(len(m.prekeyMessages)))
	for _, pm := range m.prekeyMessages {
		out = append(out, pm.serialize()...)
	}

	if m.clientProfile != nil {
		out = append(out, uint8(1))
		out = append(out, m.clientProfile.serialize()...)
	} else {
		out = append(out, uint8(0))
	}

	out = append(out, uint8(len(m.prekeyProfiles)))
	for _, pp := range m.prekeyProfiles {
		out = append(out, pp.serialize()...)
	}

	out = append(out, m.mac[:]...)
	return out
}

func (m *publicationMessage) deserialize(buf []byte) ([]byte, bool) {
	// TODO: check deserialization
	buf, _, _ = extractShort(buf) // version
	buf = buf[1:]                 // message type

	var tmp uint8
	buf, tmp, _ = extractByte(buf)
	m.prekeyMessages = make([]*prekeyMessage, tmp)
	for ix := range m.prekeyMessages {
		m.prekeyMessages[ix] = &prekeyMessage{}
		buf, _ = m.prekeyMessages[ix].deserialize(buf)
	}

	buf, tmp, _ = extractByte(buf)
	if tmp == 1 {
		m.clientProfile = &clientProfile{}
		buf, _ = m.clientProfile.deserialize(buf)
	}

	buf, tmp, _ = extractByte(buf)
	m.prekeyProfiles = make([]*prekeyProfile, tmp)
	for ix := range m.prekeyProfiles {
		m.prekeyProfiles[ix] = &prekeyProfile{}
		buf, _ = m.prekeyProfiles[ix].deserialize(buf)
	}

	var tmpb []byte
	buf, tmpb, _ = extractFixedData(buf, 64)
	copy(m.mac[:], tmpb)

	return buf, true
}

func (m *storageInformationRequestMessage) serialize() []byte {
	out := appendShort(nil, version)
	out = append(out, messageTypeStorageInformationRequest)
	out = append(out, m.mac[:]...)
	return out
}

func (m *storageInformationRequestMessage) deserialize(buf []byte) ([]byte, bool) {
	// TODO: check deserialization
	buf, _, _ = extractShort(buf) // version
	buf = buf[1:]                 // message type

	var tmp []byte
	buf, tmp, _ = extractFixedData(buf, 64)
	copy(m.mac[:], tmp)

	return buf, true
}

func (m *storageStatusMessage) serialize() []byte {
	out := appendShort(nil, version)
	out = append(out, messageTypeStorageStatusMessage)
	out = appendWord(out, m.instanceTag)
	out = appendWord(out, m.number)
	out = append(out, m.mac[:]...)
	return out
}

func (m *storageStatusMessage) deserialize(buf []byte) ([]byte, bool) {
	// TODO: check deserialization
	buf, _, _ = extractShort(buf) // version
	buf = buf[1:]                 // message type

	buf, m.instanceTag, _ = extractWord(buf)
	buf, m.number, _ = extractWord(buf)
	var tmp []byte
	buf, tmp, _ = extractFixedData(buf, 64)
	copy(m.mac[:], tmp)

	return buf, true
}

func (m *successMessage) serialize() []byte {
	out := appendShort(nil, version)
	out = append(out, messageTypeSuccess)
	out = appendWord(out, m.instanceTag)
	out = append(out, m.mac[:]...)
	return out
}

func (m *successMessage) deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	buf, v, ok := extractShort(buf)
	if !ok || v != version {
		return buf, false
	}

	if len(buf) < 1 || buf[0] != messageTypeSuccess {
		return buf, false
	}
	buf = buf[1:]

	if buf, m.instanceTag, ok = extractWord(buf); !ok {
		return nil, false
	}

	var tmp []byte
	if buf, tmp, ok = extractFixedData(buf, 64); !ok {
		return nil, false
	}
	copy(m.mac[:], tmp)

	return buf, true
}

func (m *failureMessage) serialize() []byte {
	out := appendShort(nil, version)
	out = append(out, messageTypeFailure)
	out = appendWord(out, m.instanceTag)
	out = append(out, m.mac[:]...)
	return out
}

func (m *failureMessage) deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	buf, v, ok := extractShort(buf)
	if !ok || v != version {
		return buf, false
	}

	if len(buf) < 1 || buf[0] != messageTypeFailure {
		return buf, false
	}
	buf = buf[1:]

	if buf, m.instanceTag, ok = extractWord(buf); !ok {
		return nil, false
	}

	var tmp []byte
	if buf, tmp, ok = extractFixedData(buf, 64); !ok {
		return nil, false
	}
	copy(m.mac[:], tmp)

	return buf, true
}

func (m *ensembleRetrievalQueryMessage) serialize() []byte {
	out := appendShort(nil, version)
	out = append(out, messageTypeEnsembleRetrievalQuery)
	out = appendWord(out, m.instanceTag)
	out = appendData(out, []byte(m.identity))
	out = appendData(out, m.versions)
	return out
}

func (m *ensembleRetrievalQueryMessage) deserialize(buf []byte) ([]byte, bool) {
	// TODO: check deserialization
	buf, _, _ = extractShort(buf) // version
	buf = buf[1:]                 // message type

	buf, m.instanceTag, _ = extractWord(buf)

	var tmp []byte
	buf, tmp, _ = extractData(buf)
	m.identity = string(tmp)

	buf, m.versions, _ = extractData(buf)

	return buf, true
}

func (m *ensembleRetrievalMessage) serialize() []byte {
	out := appendShort(nil, version)
	out = append(out, messageTypeEnsembleRetrieval)
	out = appendWord(out, m.instanceTag)
	out = append(out, uint8(len(m.ensembles)))
	for _, pe := range m.ensembles {
		out = append(out, pe.serialize()...)
	}

	return out
}

func (m *ensembleRetrievalMessage) deserialize(buf []byte) ([]byte, bool) {
	// TODO: check deserialization
	buf, _, _ = extractShort(buf) // version
	buf = buf[1:]                 // message type

	buf, m.instanceTag, _ = extractWord(buf)

	var tmp uint8
	buf, tmp, _ = extractByte(buf)
	m.ensembles = make([]*prekeyEnsemble, tmp)
	for ix := range m.ensembles {
		m.ensembles[ix] = &prekeyEnsemble{}
		buf, _ = m.ensembles[ix].deserialize(buf)
	}

	return buf, true
}

func (m *noPrekeyEnsemblesMessage) serialize() []byte {
	out := appendShort(nil, version)
	out = append(out, messageTypeNoPrekeyEnsembles)
	out = appendWord(out, m.instanceTag)
	out = appendData(out, []byte(m.message))
	return out
}

func (m *noPrekeyEnsemblesMessage) deserialize(buf []byte) ([]byte, bool) {
	// TODO: check deserialization
	buf, _, _ = extractShort(buf) // version
	buf = buf[1:]                 // message type

	buf, m.instanceTag, _ = extractWord(buf)
	var tmp []byte
	buf, tmp, _ = extractData(buf)
	m.message = string(tmp)

	return buf, true
}

func serializeVersions(v []byte) []byte {
	return appendData(nil, v)
}

func serializeExpiry(t time.Time) []byte {
	val := t.Unix()
	return appendLong(nil, uint64(val))
}

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

func (p *publicKey) serialize() []byte {
	return p.k.DSAEncode()
}

func (s *eddsaSignature) serialize() []byte {
	return s.s[:]
}

func serializePoint(p ed448.Point) []byte {
	return p.DSAEncode()
}

func deserializePoint(buf []byte) ([]byte, ed448.Point, bool) {
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
	tp = ed448.PointScalarMul(tp, OneFourth)
	return buf[57:], tp, true
}

func (p *publicKey) deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	buf, p.k, ok = deserializePoint(buf)
	return buf, ok
}

func (s *eddsaSignature) deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	var res []byte
	if buf, res, ok = extractFixedData(buf, 114); !ok {
		return nil, false
	}
	copy(s.s[:], res)
	return buf, true
}

func serializeScalar(s ed448.Scalar) []byte {
	return s.Encode()
}

func deserializeScalar(buf []byte) ([]byte, ed448.Scalar, bool) {
	if len(buf) < 56 {
		return nil, nil, false
	}
	ts := ed448.NewScalar()
	ts.Decode(buf[0:56])
	return buf[56:], ts, true

}

func (r *ringSignature) deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	if buf, r.c1, ok = deserializeScalar(buf); !ok {
		return nil, false
	}

	if buf, r.r1, ok = deserializeScalar(buf); !ok {
		return nil, false
	}

	if buf, r.c2, ok = deserializeScalar(buf); !ok {
		return nil, false
	}

	if buf, r.r2, ok = deserializeScalar(buf); !ok {
		return nil, false
	}

	if buf, r.c3, ok = deserializeScalar(buf); !ok {
		return nil, false
	}

	if buf, r.r3, ok = deserializeScalar(buf); !ok {
		return nil, false
	}

	return buf, true
}

func (r *ringSignature) serialize() []byte {
	var out []byte
	out = append(out, serializeScalar(r.c1)...)
	out = append(out, serializeScalar(r.r1)...)
	out = append(out, serializeScalar(r.c2)...)
	out = append(out, serializeScalar(r.r2)...)
	out = append(out, serializeScalar(r.c3)...)
	out = append(out, serializeScalar(r.r3)...)
	return out
}
