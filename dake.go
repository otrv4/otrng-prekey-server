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
