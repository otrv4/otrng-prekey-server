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
	case messageTypeEnsembleRetrievalQuery:
		r = &ensembleRetrievalQueryMessage{}
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
	num := s.storage().numberStored(from, ses.instanceTag())
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

	return nil
}

func (m *ensembleRetrievalQueryMessage) respond(from string, s *GenericServer) (serializable, error) {
	stor := s.storage()
	bundles := stor.retrieveFor(m.identity)
	if len(bundles) == 0 {
		return &noPrekeyEnsemblesMessage{
			instanceTag: m.instanceTag,
			message:     noPrekeyMessagesAvailableMessage,
		}, nil
	}
	return &ensembleRetrievalMessage{
		instanceTag: m.instanceTag,
		ensembles:   bundles,
	}, nil
}

func generateMACForPublicationMessage(cp *clientProfile, pps []*prekeyProfile, pms []*prekeyMessage, macKey []byte) []byte {
	kpms := kdfx(usagePrekeyMessage, 64, serializePrekeyMessages(pms))
	kpps := kdfx(usagePrekeyProfile, 64, serializePrekeyProfiles(pps))
	k := []byte{byte(0)}
	kcp := []byte{}
	if cp != nil {
		k = []byte{1}
		kcp = kdfx(usageClientProfile, 64, cp.serialize())
	}

	return kdfx(usagePreMAC, 64, concat(macKey, []byte{messageTypePublication, byte(len(pms))}, kpms, k, kcp, []byte{byte(len(pps))}, kpps))
}

func generatePublicationMessage(cp *clientProfile, pps []*prekeyProfile, pms []*prekeyMessage, macKey []byte) *publicationMessage {
	mac := generateMACForPublicationMessage(cp, pps, pms, macKey)
	pm := &publicationMessage{
		prekeyMessages: pms,
		clientProfile:  cp,
		prekeyProfiles: pps,
	}
	copy(pm.mac[:], mac)
	return pm
}

func (m *publicationMessage) validate(from string, s *GenericServer) error {
	macKey := s.session(from).macKey()
	clientProfile := s.session(from).clientProfile()
	mac := generateMACForPublicationMessage(m.clientProfile, m.prekeyProfiles, m.prekeyMessages, macKey)
	if !bytes.Equal(mac[:], m.mac[:]) {
		return errors.New("invalid mac for publication message")
	}

	tag := s.session(from).instanceTag()
	if m.clientProfile != nil && m.clientProfile.validate(tag) != nil {
		return errors.New("invalid client profile in publication message")
	}

	for _, pp := range m.prekeyProfiles {
		if pp.validate(tag, clientProfile.publicKey) != nil {
			return errors.New("invalid prekey profile in publication message")
		}
	}

	for _, pm := range m.prekeyMessages {
		if pm.validate(tag) != nil {
			return errors.New("invalid prekey message in publication message")
		}
	}

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
