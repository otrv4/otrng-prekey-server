package prekeyserver

import (
	"errors"

	"github.com/otrv4/ed448"
	"github.com/otrv4/gotrx"
)

type dake1Message struct {
	instanceTag   uint32
	clientProfile *gotrx.ClientProfile
	i             ed448.Point
}

type dake2Message struct {
	instanceTag    uint32
	serverIdentity []byte
	serverKey      ed448.Point
	s              ed448.Point
	sigma          *gotrx.RingSignature
}

type dake3Message struct {
	instanceTag uint32
	sigma       *gotrx.RingSignature
	message     []byte // can be either publication or storage information request
}

func generateDake1(it uint32, cp *gotrx.ClientProfile, i ed448.Point) *dake1Message {
	return &dake1Message{
		instanceTag:   it,
		clientProfile: cp,
		i:             i,
	}
}

func generateDake2(it uint32, si []byte, sk ed448.Point, s ed448.Point, sigma *gotrx.RingSignature) *dake2Message {
	return &dake2Message{
		instanceTag:    it,
		serverIdentity: si,
		serverKey:      sk,
		s:              s,
		sigma:          sigma,
	}
}

func generateDake3(it uint32, sigma *gotrx.RingSignature, m []byte) *dake3Message {
	return &dake3Message{
		instanceTag: it,
		sigma:       sigma,
		message:     m,
	}
}

func (m *dake1Message) validate(string, *GenericServer) error {
	if e := m.clientProfile.Validate(m.instanceTag); e != nil {
		return errors.New("invalid client profile")
	}

	if e := gotrx.ValidatePoint(m.i); e != nil {
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

	phi := gotrx.AppendData(gotrx.AppendData(nil, []byte(from)), []byte(s.identity))

	t := append([]byte{}, 0x01)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverClientProfile, 64, sess.clientProfile().Serialize())...)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverPrekeyCompositeIdentity, 64, s.compositeIdentity())...)
	t = append(t, gotrx.SerializePoint(sess.pointI())...)
	t = append(t, gotrx.SerializePoint(sess.keypairS().Pub.K())...)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverPrekeyCompositePHI, 64, phi)...)

	if !m.sigma.Verify(sess.clientProfile().PublicKey, s.key.Pub, sess.keypairS().Pub, t, gotrx.KdfPrekeyServer, usageAuth) {
		return errors.New("incorrect ring signature")
	}

	return nil
}

func (m *dake1Message) respond(from string, s *GenericServer) (serializable, error) {
	sk := gotrx.GenerateKeypair(s)
	s.session(from).save(sk, m.i, m.instanceTag, m.clientProfile)

	phi := gotrx.AppendData(gotrx.AppendData(nil, []byte(from)), []byte(s.identity))

	t := append([]byte{}, 0x00)
	t = append(t, gotrx.KdfPrekeyServer(usageInitiatorClientProfile, 64, m.clientProfile.Serialize())...)
	t = append(t, gotrx.KdfPrekeyServer(usageInitiatorPrekeyCompositeIdentity, 64, s.compositeIdentity())...)
	t = append(t, gotrx.SerializePoint(m.i)...)
	t = append(t, gotrx.SerializePoint(sk.Pub.K())...)
	t = append(t, gotrx.KdfPrekeyServer(usageInitiatorPrekeyCompositePHI, 64, phi)...)

	sigma, e := gotrx.GenerateSignature(s, s.key.Priv, s.key.Pub, m.clientProfile.PublicKey, s.key.Pub, gotrx.CreatePublicKey(m.i, gotrx.Ed448Key), t, gotrx.KdfPrekeyServer, usageAuth)
	if e != nil {
		return nil, errors.New("invalid ring signature generation")
	}

	return generateDake2(m.instanceTag, []byte(s.identity), s.key.Pub.K(), sk.Pub.K(), sigma), nil
}

func (m *dake1Message) respondError(from string, e error, s *GenericServer) (serializable, error) {
	return nil, e
}

func (m *dake3Message) respond(from string, s *GenericServer) (serializable, error) {
	return s.messageHandler.handleInnerMessage(from, m.message)
}

func (m *dake3Message) respondError(from string, e error, s *GenericServer) (serializable, error) {
	return nil, e
}
