package prekeyserver

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/coyim/gotrax"
)

type publicationMessage struct {
	prekeyMessages []*prekeyMessage
	clientProfile  *gotrax.ClientProfile
	prekeyProfile  *prekeyProfile
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
	validate(string, *GenericServer) error
	respond(string, *GenericServer) (serializable, error)
}

func parseVersion(message []byte) uint16 {
	_, v, _ := gotrax.ExtractShort(message)
	return v
}

func parseMessage(msg []byte) (message, uint8, error) {
	if len(msg) <= indexOfMessageType {
		return nil, 0, errors.New("message too short to be a valid message")
	}

	if v := parseVersion(msg); v != uint16(4) {
		return nil, 0, errors.New("invalid protocol version")
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
		return nil, 0, fmt.Errorf("unknown message type: 0x%x", messageType)
	}

	r.deserialize(msg)

	return r, messageType, nil
}

func generateStorageInformationRequestMessage(macKey []byte) *storageInformationRequestMessage {
	mac := gotrax.KdfPrekeyServer(usageStorageInfoMAC, 64, macKey, []byte{messageTypeStorageInformationRequest})
	res := &storageInformationRequestMessage{}
	copy(res.mac[:], mac)
	return res
}

func (m *storageInformationRequestMessage) respond(from string, s *GenericServer) (serializable, error) {
	ses := s.session(from)
	num := s.storage().numberStored(from, ses.instanceTag())
	itag := ses.instanceTag()
	prekeyMacK := ses.macKey()
	statusMac := gotrax.KdfPrekeyServer(usageStatusMAC, 64, prekeyMacK, []byte{messageTypeStorageStatusMessage}, gotrax.SerializeWord(itag), gotrax.SerializeWord(num))

	ret := &storageStatusMessage{
		instanceTag: itag,
		number:      num,
	}
	copy(ret.mac[:], statusMac)

	return ret, nil
}

func (m *storageInformationRequestMessage) validate(from string, s *GenericServer) error {
	prekeyMacK := s.session(from).macKey()
	tag := gotrax.KdfPrekeyServer(usageStorageInfoMAC, 64, prekeyMacK, []byte{messageTypeStorageInformationRequest})
	if !bytes.Equal(tag, m.mac[:]) {
		return errors.New("incorrect MAC")
	}

	return nil
}

func (m *ensembleRetrievalQueryMessage) validate(from string, s *GenericServer) error {
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

func generateMACForPublicationMessage(cp *gotrax.ClientProfile, pp *prekeyProfile, pms []*prekeyMessage, macKey []byte) []byte {
	kpms := gotrax.KdfPrekeyServer(usagePrekeyMessage, 64, serializePrekeyMessages(pms))
	kpps := gotrax.KdfPrekeyServer(usagePrekeyProfile, 64, pp.serialize())
	k := []byte{byte(0)}
	kcp := []byte{}
	if cp != nil {
		k = []byte{1}
		kcp = gotrax.KdfPrekeyServer(usageClientProfile, 64, cp.Serialize())
	}

	ppLen := 0
	if pp != nil {
		ppLen = 1
	}

	d := append(macKey, messageTypePublication)
	d = append(d, byte(len(pms)))
	d = append(d, kpms...)
	d = append(d, k...)
	d = append(d, kcp...)
	d = append(d, byte(ppLen))
	d = append(d, kpps...)
	return gotrax.KdfPrekeyServer(usagePreMAC, 64, d)
}

func generatePublicationMessage(cp *gotrax.ClientProfile, pp *prekeyProfile, pms []*prekeyMessage, macKey []byte) *publicationMessage {
	mac := generateMACForPublicationMessage(cp, pp, pms, macKey)
	pm := &publicationMessage{
		prekeyMessages: pms,
		clientProfile:  cp,
		prekeyProfile:  pp,
	}
	copy(pm.mac[:], mac)
	return pm
}

func (m *publicationMessage) validate(from string, s *GenericServer) error {
	macKey := s.session(from).macKey()
	clientProfile := s.session(from).clientProfile()
	mac := generateMACForPublicationMessage(m.clientProfile, m.prekeyProfile, m.prekeyMessages, macKey)
	if !bytes.Equal(mac[:], m.mac[:]) {
		return errors.New("invalid mac for publication message")
	}

	tag := s.session(from).instanceTag()
	if m.clientProfile != nil && m.clientProfile.Validate(tag) != nil {
		return errors.New("invalid client profile in publication message")
	}

	if m.prekeyProfile != nil && m.prekeyProfile.validate(tag, clientProfile.PublicKey) != nil {
		return errors.New("invalid prekey profile in publication message")
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

	mac := gotrax.KdfPrekeyServer(usageSuccessMAC, 64, gotrax.AppendWord(append(macKey, messageTypeSuccess), tag))
	copy(m.mac[:], mac)

	return m
}

func (m *publicationMessage) respond(from string, s *GenericServer) (serializable, error) {
	stor := s.storage()
	stor.storeClientProfile(from, m.clientProfile)
	stor.storePrekeyProfile(from, m.prekeyProfile)
	stor.storePrekeyMessages(from, m.prekeyMessages)

	macKey := s.session(from).macKey()
	instanceTag := s.session(from).instanceTag()

	s.sessionComplete(from)

	return generateSuccessMessage(macKey, instanceTag), nil
}
