package prekeyserver

import "github.com/twstrike/ed448"

type dake1Message struct {
	instanceTag   uint32
	clientProfile *clientProfile
	i             ed448.Point
}

func (m *dake1Message) deserialize([]byte) error {
	panic("implement me")
	return nil
}

type dake2Message struct {
	instanceTag    uint32
	serverIdentity []byte
	s              ed448.Point
	sigma          *ringSignature
}

func (m *dake2Message) deserialize([]byte) error {
	panic("implement me")
	return nil
}

type dake3Message struct {
	instanceTag uint32
	sigma       *ringSignature
	message     []byte // can be either publication or storage information request
}

func (m *dake3Message) deserialize([]byte) error {
	panic("implement me")
	return nil
}
