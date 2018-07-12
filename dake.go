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

func (m *dake1Message) validate(string, *GenericServer) error {
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

	if len(m.message) == 0 {
		return errors.New("incorrect message")
	}

	phi := appendData(appendData(nil, []byte(from)), []byte(s.identity))

	t := append([]byte{}, 0x01)
	t = append(t, kdfx(usageReceiverClientProfile, 64, sess.clientProfile().serialize())...)
	t = append(t, kdfx(usageReceiverPrekeyCompositeIdentity, 64, s.compositeIdentity())...)
	t = append(t, serializePoint(sess.pointI())...)
	t = append(t, serializePoint(sess.keypairS().pub.k)...)
	t = append(t, kdfx(usageReceiverPrekeyCompositePHI, 64, phi)...)

	if !m.sigma.verify(sess.clientProfile().publicKey, s.key.pub, sess.keypairS().pub, t) {
		return errors.New("incorrect ring signature")
	}

	return nil
}

func (m *dake1Message) respond(from string, s *GenericServer) (serializable, error) {
	sk := generateECDHKeypair(s)
	s.session(from).save(sk, m.i, m.instanceTag, m.clientProfile)

	phi := appendData(appendData(nil, []byte(from)), []byte(s.identity))

	t := append([]byte{}, 0x00)
	t = append(t, kdfx(usageInitiatorClientProfile, 64, m.clientProfile.serialize())...)
	t = append(t, kdfx(usageInitiatorPrekeyCompositeIdentity, 64, s.compositeIdentity())...)
	t = append(t, serializePoint(m.i)...)
	t = append(t, serializePoint(sk.pub.k)...)
	t = append(t, kdfx(usageInitiatorPrekeyCompositePHI, 64, phi)...)

	sigma, e := generateSignature(s, s.key.priv, s.key.pub, m.clientProfile.publicKey, s.key.pub, &publicKey{m.i}, t)
	if e != nil {
		return nil, errors.New("invalid ring signature generation")
	}

	return generateDake2(m.instanceTag, []byte(s.identity), s.fingerprint, sk.pub.k, sigma), nil
}

func (m *dake3Message) respond(from string, s *GenericServer) (serializable, error) {
	return s.messageHandler.handleInnerMessage(from, m.message)
}
