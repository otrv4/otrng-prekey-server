package prekeyserver

import (
	"bytes"
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
	case messageTypeDAKE3:
		r = &dake3Message{}
	case messageTypePublication:
		r = &publicationMessage{}
	case messageTypeStorageInformationRequest:
		r = &storageInformationRequestMessage{}
	// case messageTypeStorageStatusMessage:
	// 	r = &storageStatusMessage{}
	// case messageTypeSuccess:
	// 	r = &successMessage{}
	// case messageTypeFailure:
	// 	r = &failureMessage{}
	case messageTypeEnsembleRetrievalQuery:
		r = &ensembleRetrievalQueryMessage{}
	// case messageTypeEnsembleRetrieval:
	// 	r = &ensembleRetrievalMessage{}
	// case messageTypeNoPrekeyEnsembles:
	// 	r = &noPrekeyEnsemblesMessage{}
	default:
		return nil, fmt.Errorf("unknown message type: 0x%x", messageType)
	}

	r.deserialize(msg)

	return r, nil
}

func generateStorageInformationRequestMessage(macKey []byte) *storageInformationRequestMessage {
	mac := kdfx(usageStorageInfoMAC, 64, macKey, []byte{messageTypeStorageInformationRequest})
	res := &storageInformationRequestMessage{}
	copy(res.mac[:], mac)
	return res
}

func (m *storageInformationRequestMessage) respond(from string, s *GenericServer) (serializable, error) {
	ses := s.session(from)
	// TODO: should be contingent of instance tags and public keys used during DAKE
	num := ses.numberStored()
	itag := ses.instanceTag()
	prekeyMacK := ses.macKey()
	statusMac := kdfx(usageStatusMAC, 64, prekeyMacK, []byte{messageTypeStorageStatusMessage}, serializeWord(itag), serializeWord(num))

	ret := &storageStatusMessage{
		instanceTag: itag,
		number:      num,
	}
	copy(ret.mac[:], statusMac)

	return ret, nil
}

func (m *storageInformationRequestMessage) validate(from string, s *GenericServer) error {
	prekeyMacK := s.session(from).macKey()
	tag := kdfx(usageStorageInfoMAC, 64, prekeyMacK, []byte{messageTypeStorageInformationRequest})
	if !bytes.Equal(tag, m.mac[:]) {
		return errors.New("incorrect MAC")
	}

	// TODO: implement rest

	return nil
}

func (m *ensembleRetrievalQueryMessage) respond(from string, s *GenericServer) (serializable, error) {
	return &noPrekeyEnsemblesMessage{
		instanceTag: m.instanceTag,
		message:     noPrekeyMessagesAvailableMessage,
	}, nil
}

func generatePublicationMessage(cp *clientProfile, pps []*prekeyProfile, pms []*prekeyMessage, macKey []byte) *publicationMessage {
	kpms := kdfx(usagePrekeyMessage, 64, serializePrekeyMessages(pms))
	kpps := kdfx(usagePrekeyProfile, 64, serializePrekeyProfiles(pps))
	k := []byte{byte(0)}
	kcp := []byte{}
	if cp != nil {
		k = []byte{1}
		kcp = kdfx(usageClientProfile, 64, cp.serialize())
	}

	mac := kdfx(usagePreMAC, 64, concat(macKey, []byte{messageTypePublication, byte(len(pms))}, kpms, k, kcp, []byte{byte(len(pps))}, kpps))
	pm := &publicationMessage{
		prekeyMessages: pms,
		clientProfile:  cp,
		prekeyProfiles: pps,
	}
	copy(pm.mac[:], mac)
	return pm
}

func (m *publicationMessage) validate(from string, s *GenericServer) error {
	// TODO: implement
	// The Prekey Server verifies the received values:
	// Validate the Prekey Publication message, as defined in its section Prekey Publication Message.
	// For every value, check the integrity of it.
	// If Client and Prekey Profile are present:
	// Validate the Client Profile as defined in the Validating a Client Profile section of the OTRv4 specification.
	// Validate the Prekey Profile as defined in the Validating a Prekey Profile section of the OTRv4 specification.
	// If Prekey Messages are present:
	// Validate the Prekey Messages as defined in the Prekey Message section of the OTRv4 specification.
	// Discard any invalid or duplicated values.
	return nil
}

func generateSuccessMessage(macKey []byte, tag uint32) *successMessage {
	m := &successMessage{
		instanceTag: tag,
	}

	mac := kdfx(usageSuccessMAC, 64, appendWord(append(macKey, messageTypeSuccess), tag))
	copy(m.mac[:], mac)

	return m
}

func (m *publicationMessage) respond(from string, s *GenericServer) (serializable, error) {
	stor := s.storage()
	stor.storeClientProfile(from, m.clientProfile)
	stor.storePrekeyProfiles(from, m.prekeyProfiles)
	stor.storePrekeyMessages(from, m.prekeyMessages)

	macKey := s.session(from).macKey()
	instanceTag := s.session(from).instanceTag()

	// TODO: session should be removed here

	return generateSuccessMessage(macKey, instanceTag), nil
}
