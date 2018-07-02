package prekeyserver

import (
	"errors"
	"fmt"
)

const macLength = 64

type publicationMessage struct {
	prekeyMessages []*prekeyMessage
	clientProfile  *clientProfile
	prekeyProfiles []*prekeyProfile
	mac            [macLength]byte
}

func (m *publicationMessage) deserialize([]byte) ([]byte, bool) {
	// TODO: implement
	panic("implement me")
	return nil, false
}

type storageInformationRequestMessage struct {
	mac [macLength]byte
}

func (m *storageInformationRequestMessage) deserialize([]byte) ([]byte, bool) {
	// TODO: implement
	panic("implement me")
	return nil, false
}

type storageStatusMessage struct {
	instanceTag uint32
	number      uint32
	mac         [macLength]byte
}

func (m *storageStatusMessage) deserialize([]byte) ([]byte, bool) {
	// TODO: implement
	panic("implement me")
	return nil, false
}

type successMessage struct {
	instanceTag uint32
	mac         [macLength]byte
}

func (m *successMessage) deserialize([]byte) ([]byte, bool) {
	// TODO: implement
	panic("implement me")
	return nil, false
}

type failureMessage struct {
	instanceTag uint32
	mac         [macLength]byte
}

func (m *failureMessage) deserialize([]byte) ([]byte, bool) {
	// TODO: implement
	panic("implement me")
	return nil, false
}

type ensembleRetrievalQueryMessage struct {
	instanceTag uint32
	identity    string
	versions    []byte
}

func (m *ensembleRetrievalQueryMessage) deserialize([]byte) ([]byte, bool) {
	panic("implement me")
	return nil, false
}

type ensembleRetrievalMessage struct {
	instanceTag uint32
	ensembles   []*prekeyEnsemble
}

func (m *ensembleRetrievalMessage) deserialize([]byte) ([]byte, bool) {
	// TODO: implement
	panic("implement me")
	return nil, false
}

type noPrekeyEnsemblesMessage struct {
	instanceTag uint32
	message     string
}

func (m *noPrekeyEnsemblesMessage) deserialize([]byte) ([]byte, bool) {
	// TODO: implement
	panic("implement me")
	return nil, false
}

type serializable interface {
	deserialize([]byte) ([]byte, bool)
	//	serialize() ([]byte, error)
}

type message interface {
	serializable
	//	validate() error
}

var (
	messageTypeDAKE1                     = uint8(0x01)
	messageTypeDAKE2                     = uint8(0x02)
	messageTypeDAKE3                     = uint8(0x03)
	messageTypePublication               = uint8(0x04)
	messageTypeStorageInformationRequest = uint8(0x05)
	messageTypeStorageStatusMessage      = uint8(0x06)
	messageTypeSuccess                   = uint8(0x07)
	messageTypeFailure                   = uint8(0x08)
	messageTypeEnsembleRetrievalQuery    = uint8(0x09)
	messageTypeEnsembleRetrieval         = uint8(0x10)
	messageTypeNoPrekeyEnsembles         = uint8(0x11)
)

const indexOfMessageType = 2
const indexContentStarts = 2

func parseVersion(message []byte) uint16 {
	_, v, _ := extractShort(message)
	return v
}

func parseMessage(msg []byte) (interface{}, error) {
	if len(msg) <= indexOfMessageType {
		return nil, errors.New("message too short to be a valid message")
	}

	if v := parseVersion(msg); v != uint16(4) {
		return nil, errors.New("invalid protocol version")
	}

	messageType := msg[indexOfMessageType]

	var r message
	switch messageType {
	case messageTypeDAKE1:
		r = &dake1Message{}
	case messageTypeDAKE2:
		r = &dake2Message{}
	case messageTypeDAKE3:
		r = &dake3Message{}
	case messageTypePublication:
		r = &publicationMessage{}
	case messageTypeStorageInformationRequest:
		r = &storageInformationRequestMessage{}
	case messageTypeStorageStatusMessage:
		r = &storageStatusMessage{}
	case messageTypeSuccess:
		r = &successMessage{}
	case messageTypeFailure:
		r = &failureMessage{}
	case messageTypeEnsembleRetrievalQuery:
		r = &ensembleRetrievalQueryMessage{}
	case messageTypeEnsembleRetrieval:
		r = &ensembleRetrievalMessage{}
	case messageTypeNoPrekeyEnsembles:
		r = &noPrekeyEnsemblesMessage{}
	default:
		return nil, fmt.Errorf("unknown message type: 0x%x", messageType)
	}

	r.deserialize(msg[indexContentStarts:])

	return r, nil
}

// What messages can we as a server receive at the top level?

// DAKE1
// DAKE3
// ensembleRetrievalQueryMessage

// What messages are NOT top level?
//    publicationMessage
//    storageInformationRequestMessage

// What messages can we as a server SEND:
// DAKE2
// storageStatusMessage
// successMessage
// failureMessage
// ensembleRetrievalMessage
// noPrekeyEnsemblesMessage
