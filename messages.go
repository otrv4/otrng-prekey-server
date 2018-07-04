package prekeyserver

import (
	"errors"
	"fmt"
)

type publicationMessage struct {
	prekeyMessages []*prekeyMessage
	clientProfile  *clientProfile
	prekeyProfiles []*prekeyProfile
	mac            [macLength]byte
}

type storageInformationRequestMessage struct {
	mac [macLength]byte
}

type storageStatusMessage struct {
	instanceTag uint32
	number      uint32
	mac         [macLength]byte
}

type successMessage struct {
	instanceTag uint32
	mac         [macLength]byte
}

type failureMessage struct {
	instanceTag uint32
	mac         [macLength]byte
}

type ensembleRetrievalQueryMessage struct {
	instanceTag uint32
	identity    string
	versions    []byte
}

type ensembleRetrievalMessage struct {
	instanceTag uint32
	ensembles   []*prekeyEnsemble
}

type noPrekeyEnsemblesMessage struct {
	instanceTag uint32
	message     string
}

type message interface {
	serializable
}

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

	r.deserialize(msg)

	return r, nil
}
