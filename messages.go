package prekeyserver

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/otrv4/gotrx"
)

type publicationMessage struct {
	prekeyMessages         []*prekeyMessage
	clientProfile          *gotrx.ClientProfile
	prekeyProfile          *prekeyProfile
	prekeyMessageProofEcdh *ecdhProof
	prekeyMessageProofDh   *dhProof
	prekeyProfileProofEcdh *ecdhProof
	mac                    [macLength]byte
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
	identity    string
	ensembles   []*prekeyEnsemble
}

type noPrekeyEnsemblesMessage struct {
	instanceTag uint32
	identity    string
	message     string
}

type message interface {
	serializable
	validate(string, *GenericServer) error
	respond(string, *GenericServer) (serializable, error)
	respondError(string, error, *GenericServer) (serializable, error)
}

func parseVersion(message []byte) uint16 {
	_, v, _ := gotrx.ExtractShort(message)
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
	mac := gotrx.KdfPrekeyServer(usageStorageInfoMAC, 64, macKey, []byte{messageTypeStorageInformationRequest})
	res := &storageInformationRequestMessage{}
	copy(res.mac[:], mac)
	return res
}

func (m *storageInformationRequestMessage) respond(from string, s *GenericServer) (serializable, error) {
	ses := s.session(from)
	num := s.storage().numberStored(from, ses.instanceTag())
	itag := ses.instanceTag()
	prekeyMacK := ses.macKey()
	statusMac := gotrx.KdfPrekeyServer(usageStatusMAC, 64, prekeyMacK, []byte{messageTypeStorageStatusMessage}, gotrx.SerializeWord(itag), gotrx.SerializeWord(num))

	ret := &storageStatusMessage{
		instanceTag: itag,
		number:      num,
	}
	copy(ret.mac[:], statusMac)

	return ret, nil
}

func (m *storageInformationRequestMessage) respondError(from string, e error, s *GenericServer) (serializable, error) {
	return nil, e
}

func (m *storageInformationRequestMessage) validate(from string, s *GenericServer) error {
	prekeyMacK := s.session(from).macKey()
	tag := gotrx.KdfPrekeyServer(usageStorageInfoMAC, 64, prekeyMacK, []byte{messageTypeStorageInformationRequest})
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
			identity:    m.identity,
			message:     noPrekeyMessagesAvailableMessage,
		}, nil
	}
	return &ensembleRetrievalMessage{
		instanceTag: m.instanceTag,
		identity:    m.identity,
		ensembles:   bundles,
	}, nil
}

func (m *ensembleRetrievalQueryMessage) respondError(from string, e error, s *GenericServer) (serializable, error) {
	return nil, e
}

func serializeProofs(prof1 *ecdhProof, prof2 *dhProof, prof3 *ecdhProof) []byte {
	out := []byte{}
	if prof1 != nil {
		out = append(out, prof1.serialize()...)
	}
	if prof2 != nil {
		out = append(out, prof2.serialize()...)
	}
	if prof3 != nil {
		out = append(out, prof3.serialize()...)
	}
	return out
}

func generateMACForPublicationMessage(cp *gotrx.ClientProfile, pp *prekeyProfile, pms []*prekeyMessage, prof1 *ecdhProof, prof2 *dhProof, prof3 *ecdhProof, macKey []byte) []byte {
	kpms := gotrx.KdfPrekeyServer(usagePrekeyMessage, 64, serializePrekeyMessages(pms))
	k := byte(0)
	kcp := []byte{}
	if cp != nil {
		k = 1
		kcp = gotrx.KdfPrekeyServer(usageClientProfile, 64, cp.Serialize())
	}

	j := byte(0)
	kpps := []byte{}
	if pp != nil {
		j = 1
		kpps = gotrx.KdfPrekeyServer(usagePrekeyProfile, 64, pp.serialize())
	}

	pfs := gotrx.KdfPrekeyServer(usageMacProofs, 64, serializeProofs(prof1, prof2, prof3))

	d := append(macKey, messageTypePublication)
	d = append(d, byte(len(pms)))
	d = append(d, kpms...)
	d = append(d, k)
	d = append(d, kcp...)
	d = append(d, j)
	d = append(d, kpps...)
	d = append(d, pfs...)

	return gotrx.KdfPrekeyServer(usagePreMAC, 64, d)
}

func generatePrekeyMessagesProofs(wr gotrx.WithRandom, ecdhKeys []*gotrx.Keypair, dhPriv []*big.Int, dhPub []*big.Int, sk []byte) (*ecdhProof, *dhProof) {
	if len(ecdhKeys) == 0 {
		return nil, nil
	}
	m := gotrx.KdfPrekeyServer(usageProofContext, 64, sk)
	prof1, _ := generateEcdhProof(wr, ecdhKeys, m, usageProofMessageEcdh)
	prof2, _ := generateDhProof(wr, dhPriv, dhPub, m, usageProofMessageDh, nil)
	return prof1, prof2
}

func gemeratePrekeyProfileProof(wr gotrx.WithRandom, ecdhKey *gotrx.Keypair, sk []byte) *ecdhProof {
	if ecdhKey == nil {
		return nil
	}
	m := gotrx.KdfPrekeyServer(usageProofContext, 64, sk)
	prof, _ := generateEcdhProof(wr, []*gotrx.Keypair{ecdhKey}, m, usageProofSharedEcdh)
	return prof
}

func generatePublicationMessage(cp *gotrx.ClientProfile, pp *prekeyProfile, pms []*prekeyMessage, prof1 *ecdhProof, prof2 *dhProof, prof3 *ecdhProof, macKey []byte) *publicationMessage {
	mac := generateMACForPublicationMessage(cp, pp, pms, prof1, prof2, prof3, macKey)

	pm := &publicationMessage{
		prekeyMessages:         pms,
		clientProfile:          cp,
		prekeyProfile:          pp,
		prekeyMessageProofEcdh: prof1,
		prekeyMessageProofDh:   prof2,
		prekeyProfileProofEcdh: prof3,
	}
	copy(pm.mac[:], mac)
	return pm
}

func (m *publicationMessage) validate(from string, s *GenericServer) error {
	macKey := s.session(from).macKey()
	sk := s.session(from).sharedSecret()
	clientProfile := s.session(from).clientProfile()
	mac := generateMACForPublicationMessage(m.clientProfile, m.prekeyProfile, m.prekeyMessages, m.prekeyMessageProofEcdh, m.prekeyMessageProofDh, m.prekeyProfileProofEcdh, macKey)

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

	ks := []*gotrx.PublicKey{}
	ks2 := []*big.Int{}
	for _, pm := range m.prekeyMessages {
		if pm.validate(tag) != nil {
			return errors.New("invalid prekey message in publication message")
		}
		ks = append(ks, gotrx.CreatePublicKey(pm.y, gotrx.Ed448Key))
		ks2 = append(ks2, pm.b)
	}

	msg := gotrx.KdfPrekeyServer(usageProofContext, 64, sk)
	if len(m.prekeyMessages) > 0 {
		if m.prekeyMessageProofEcdh == nil {
			return errors.New("missing proof for prekey messages y key")
		}
		if m.prekeyMessageProofDh == nil {
			return errors.New("missing proof for prekey messages b key")
		}

		if !m.prekeyMessageProofEcdh.verify(ks, msg, usageProofMessageEcdh) {
			return errors.New("incorrect proof for prekey messages y key")
		}

		if !m.prekeyMessageProofDh.verify(ks2, msg, usageProofMessageDh) {
			return errors.New("incorrect proof for prekey messages b key")
		}
	}

	if m.prekeyProfile != nil {
		if m.prekeyProfileProofEcdh == nil {
			return errors.New("missing proof for prekey profile shared prekey")
		}

		if !m.prekeyProfileProofEcdh.verify([]*gotrx.PublicKey{m.prekeyProfile.sharedPrekey}, msg, usageProofSharedEcdh) {
			return errors.New("incorrect proof for prekey profile shared prekey")
		}
	}

	return nil
}

func generateSuccessMessage(macKey []byte, tag uint32) *successMessage {
	m := &successMessage{
		instanceTag: tag,
	}

	mac := gotrx.KdfPrekeyServer(usageSuccessMAC, 64, gotrx.AppendWord(append(macKey, messageTypeSuccess), tag))
	copy(m.mac[:], mac)

	return m
}

func generateFailureMessage(macKey []byte, tag uint32) *failureMessage {
	m := &failureMessage{
		instanceTag: tag,
	}

	mac := gotrx.KdfPrekeyServer(usageFailureMAC, 64, gotrx.AppendWord(append(macKey, messageTypeFailure), tag))
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

func (m *publicationMessage) respondError(from string, e error, s *GenericServer) (serializable, error) {
	stor := s.storage()
	stor.storeClientProfile(from, m.clientProfile)
	stor.storePrekeyProfile(from, m.prekeyProfile)
	stor.storePrekeyMessages(from, m.prekeyMessages)

	macKey := s.session(from).macKey()
	instanceTag := s.session(from).instanceTag()

	s.sessionComplete(from)

	return generateFailureMessage(macKey, instanceTag), nil
}
