package prekeyserver

import "github.com/twstrike/ed448"

const (
	version          = uint16(4)
	dake1MessageType = uint8(0x01)
	dake2MessageType = uint8(0x02)
	dake3MessageType = uint8(0x03)
)

type dake1Message struct {
	instanceTag   uint32
	clientProfile *clientProfile
	i             ed448.Point
}

func (m *dake1Message) deserialize(buf []byte) ([]byte, bool) {
	var ok1 bool
	buf, v, ok1 := extractShort(buf) // version
	if !ok1 || v != version {
		return buf, false
	}

	if len(buf) < 1 || buf[0] != dake1MessageType {
		return buf, false
	}
	buf = buf[1:]

	buf, m.instanceTag, ok1 = extractWord(buf)
	if !ok1 {
		return buf, false
	}

	m.clientProfile = &clientProfile{}
	buf, ok1 = m.clientProfile.deserialize(buf)
	if !ok1 {
		return buf, false
	}

	buf, m.i, ok1 = deserializePoint(buf)
	if !ok1 {
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

type dake2Message struct {
	instanceTag       uint32
	serverIdentity    []byte
	serverFingerprint fingerprint
	s                 ed448.Point
	sigma             *ringSignature
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
	// TODO: check deserialization
	buf, _, _ = extractShort(buf) // version
	buf = buf[1:]                 // message type

	buf, m.instanceTag, _ = extractWord(buf)
	buf, m.serverIdentity, _ = extractData(buf)
	var tmp []byte
	buf, tmp, _ = extractData(buf)
	copy(m.serverFingerprint[:], tmp)

	buf, m.s, _ = deserializePoint(buf)

	m.sigma = &ringSignature{}
	buf, _ = m.sigma.deserialize(buf)

	return buf, true
}

type dake3Message struct {
	instanceTag uint32
	sigma       *ringSignature
	message     []byte // can be either publication or storage information request
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
	// TODO: check deserialization
	buf, _, _ = extractShort(buf) // version
	buf = buf[1:]                 // message type
	buf, m.instanceTag, _ = extractWord(buf)
	m.sigma = &ringSignature{}
	buf, _ = m.sigma.deserialize(buf)
	buf, m.message, _ = extractData(buf)
	return buf, true
}
