package prekeyserver

import (
	"errors"

	"github.com/otrv4/ed448"
)

type dake1Message struct {
	instanceTag   uint32
	clientProfile *clientProfile
	i             ed448.Point
}

type dake2Message struct {
	instanceTag       uint32
	serverIdentity    []byte
	serverFingerprint fingerprint
	s                 ed448.Point
	sigma             *ringSignature
}

type dake3Message struct {
	instanceTag uint32
	sigma       *ringSignature
	message     []byte // can be either publication or storage information request
}

func generateDake1(it uint32, cp *clientProfile, i ed448.Point) *dake1Message {
	return &dake1Message{
		instanceTag:   it,
		clientProfile: cp,
		i:             i,
	}
}

func generateDake2(it uint32, si []byte, sf fingerprint, s ed448.Point, sigma *ringSignature) *dake2Message {
	return &dake2Message{
		instanceTag:       it,
		serverIdentity:    si,
		serverFingerprint: sf,
		s:                 s,
		sigma:             sigma,
	}
}

func generateDake3(it uint32, sigma *ringSignature, m []byte) *dake3Message {
	return &dake3Message{
		instanceTag: it,
		sigma:       sigma,
		message:     m,
	}
}

func (m *dake1Message) validate() error {
	if e := m.clientProfile.validate(m.instanceTag); e != nil {
		return errors.New("invalid client profile")
	}

	if e := validatePoint(m.i); e != nil {
		return errors.New("invalid point I")
	}

	return nil
}

func (m *dake3Message) validate(from string, s *GenericServer) error {
	sess := s.session(from)
	if sess.instanceTag() != m.instanceTag {
		return errors.New("incorrect instance tag")
	}

	// TODO: implement rest
	return nil
}

func (m *dake1Message) respond(from string, s *GenericServer) (serializable, error) {
	sk := generateECDHKeypair(s)
	s.session(from).save(sk, m.i, m.instanceTag)

	// TODO: actually make a real phi
	phi := []byte("hardcoded phi for now")

	t := append([]byte{}, 0x00)
	t = append(t, kdfx(usageInitiatorClientProfile, 64, m.clientProfile.serialize())...)
	t = append(t, kdfx(usageInitiatorPrekeyCompositeIdentity, 64, s.compositeIdentity())...)
	t = append(t, serializePoint(m.i)...)
	t = append(t, serializePoint(sk.pub.k)...)
	t = append(t, kdfx(usageInitiatorPrekeyCompositePHI, 64, phi)...)

	// TODO: not ignore error here
	sigma, _ := generateSignature(s, s.key.priv, s.key.pub, m.clientProfile.publicKey, s.key.pub, &publicKey{m.i}, t)

	return generateDake2(m.instanceTag, []byte(s.identity), s.fingerprint, sk.pub.k, sigma), nil
}

func (m *dake3Message) respond(from string, s *GenericServer) (serializable, error) {
	result, e := parseMessage(m.message)
	if e != nil {
		// TODO: test
		return nil, e
	}

	if s1, ok := result.(*storageInformationRequestMessage); ok {
		if ev := s1.validate(from, s); ev != nil {
			return nil, ev
		}

		r1, e1 := s1.respond(from, s)
		if e1 != nil {
			// TODO: test
			return nil, e1
		}
		return r1, nil
	}

	if s1, ok := result.(*publicationMessage); ok {
		// TODO: s1.validate(from, s)

		r, e := s1.respond(from, s)
		if e != nil {
			// TODO: test
			return nil, e
		}
		return r, nil
	}

	return nil, nil
}
