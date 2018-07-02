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

func (m *publicationMessage) serialize() []byte {
	// TODO: implement
	panic("implement me")
	return nil
}

func (m *publicationMessage) deserialize([]byte) ([]byte, bool) {
	// TODO: implement
	panic("implement me")
	return nil, false
}

type storageInformationRequestMessage struct {
	mac [macLength]byte
}

func (m *storageInformationRequestMessage) serialize() []byte {
	out := appendShort(nil, version)
	out = append(out, messageTypeStorageInformationRequest)
	out = append(out, m.mac[:]...)
	return out
}

func (m *storageInformationRequestMessage) deserialize(buf []byte) ([]byte, bool) {
	buf, _, _ = extractShort(buf) // version
	buf = buf[1:]                 // message type

	var tmp []byte
	buf, tmp, _ = extractFixedData(buf, 64)
	copy(m.mac[:], tmp)

	return buf, true
}

type storageStatusMessage struct {
	instanceTag uint32
	number      uint32
	mac         [macLength]byte
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
	buf, _, _ = extractShort(buf) // version
	buf = buf[1:]                 // message type

	buf, m.instanceTag, _ = extractWord(buf)
	buf, m.number, _ = extractWord(buf)
	var tmp []byte
	buf, tmp, _ = extractFixedData(buf, 64)
	copy(m.mac[:], tmp)

	return buf, true
}

type successMessage struct {
	instanceTag uint32
	mac         [macLength]byte
}

func (m *successMessage) serialize() []byte {
	out := appendShort(nil, version)
	out = append(out, messageTypeSuccess)
	out = appendWord(out, m.instanceTag)
	out = append(out, m.mac[:]...)
	return out
}

func (m *successMessage) deserialize(buf []byte) ([]byte, bool) {
	buf, _, _ = extractShort(buf) // version
	buf = buf[1:]                 // message type

	buf, m.instanceTag, _ = extractWord(buf)
	var tmp []byte
	buf, tmp, _ = extractFixedData(buf, 64)
	copy(m.mac[:], tmp)

	return buf, true
}

type failureMessage struct {
	instanceTag uint32
	mac         [macLength]byte
}

func (m *failureMessage) serialize() []byte {
	out := appendShort(nil, version)
	out = append(out, messageTypeFailure)
	out = appendWord(out, m.instanceTag)
	out = append(out, m.mac[:]...)
	return out
}

func (m *failureMessage) deserialize(buf []byte) ([]byte, bool) {
	buf, _, _ = extractShort(buf) // version
	buf = buf[1:]                 // message type

	buf, m.instanceTag, _ = extractWord(buf)
	var tmp []byte
	buf, tmp, _ = extractFixedData(buf, 64)
	copy(m.mac[:], tmp)

	return buf, true
}

type ensembleRetrievalQueryMessage struct {
	instanceTag uint32
	identity    string
	versions    []byte
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
	buf, _, _ = extractShort(buf) // version
	buf = buf[1:]                 // message type

	buf, m.instanceTag, _ = extractWord(buf)

	var tmp []byte
	buf, tmp, _ = extractData(buf)
	m.identity = string(tmp)

	buf, m.versions, _ = extractData(buf)

	return buf, true
}

type ensembleRetrievalMessage struct {
	instanceTag uint32
	ensembles   []*prekeyEnsemble
}

func (m *ensembleRetrievalMessage) serialize() []byte {
	// TODO: implement
	panic("implement me")
	return nil
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

func (m *noPrekeyEnsemblesMessage) serialize() []byte {
	out := appendShort(nil, version)
	out = append(out, messageTypeNoPrekeyEnsembles)
	out = appendWord(out, m.instanceTag)
	out = appendData(out, []byte(m.message))
	return out
}

func (m *noPrekeyEnsemblesMessage) deserialize(buf []byte) ([]byte, bool) {
	buf, _, _ = extractShort(buf) // version
	buf = buf[1:]                 // message type

	buf, m.instanceTag, _ = extractWord(buf)
	var tmp []byte
	buf, tmp, _ = extractData(buf)
	m.message = string(tmp)

	return buf, true
}

type serializable interface {
	deserialize([]byte) ([]byte, bool)
	serialize() []byte
}

type message interface {
	serializable
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
	messageTypePrekeyMessage             = uint8(0x0F)
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
