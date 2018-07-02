package prekeyserver

import "github.com/twstrike/ed448"

const (
	version          = uint16(4)
	dake1MessageType = uint8(0x01)
)

type dake1Message struct {
	instanceTag   uint32
	clientProfile *clientProfile
	i             ed448.Point
}

func (m *dake1Message) deserialize(buf []byte) error {
	buf, _, _ = extractShort(buf) // version
	buf = buf[1:]                 // message type

	buf, m.instanceTag, _ = extractWord(buf)

	m.clientProfile = &clientProfile{}
	buf, _ = m.clientProfile.deserialize(buf)

	buf, m.i, _ = deserializePoint(buf)

	return nil
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
	instanceTag    uint32
	serverIdentity []byte
	s              ed448.Point
	sigma          *ringSignature
}

func (m *dake2Message) deserialize([]byte) error {
	// TODO: implement
	panic("implement me")
	return nil
}

type dake3Message struct {
	instanceTag uint32
	sigma       *ringSignature
	message     []byte // can be either publication or storage information request
}

func (m *dake3Message) deserialize([]byte) error {
	// TODO: implement
	panic("implement me")
	return nil
}
