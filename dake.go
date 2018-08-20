package prekeyserver

import (
	"errors"

	"github.com/coyim/gotrax"
	"github.com/otrv4/ed448"
)

type dake1Message struct {
	instanceTag   uint32
	clientProfile *gotrax.ClientProfile
	i             ed448.Point
}

type dake2Message struct {
	instanceTag    uint32
	serverIdentity []byte
	serverKey      ed448.Point
	s              ed448.Point
	sigma          *ringSignature
}

type dake3Message struct {
	instanceTag uint32
	sigma       *ringSignature
	message     []byte // can be either publication or storage information request
}

func generateDake1(it uint32, cp *gotrax.ClientProfile, i ed448.Point) *dake1Message {
	return &dake1Message{
		instanceTag:   it,
		clientProfile: cp,
		i:             i,
	}
}

func generateDake2(it uint32, si []byte, sk ed448.Point, s ed448.Point, sigma *ringSignature) *dake2Message {
	return &dake2Message{
		instanceTag:    it,
		serverIdentity: si,
		serverKey:      sk,
		s:              s,
		sigma:          sigma,
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
	if e := m.clientProfile.Validate(m.instanceTag); e != nil {
		return errors.New("invalid client profile")
	}

	if e := gotrax.ValidatePoint(m.i); e != nil {
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

	phi := gotrax.AppendData(gotrax.AppendData(nil, []byte(from)), []byte(s.identity))

	t := append([]byte{}, 0x01)
	t = append(t, kdfx(usageReceiverClientProfile, 64, sess.clientProfile().Serialize())...)
	t = append(t, kdfx(usageReceiverPrekeyCompositeIdentity, 64, s.compositeIdentity())...)
	t = append(t, gotrax.SerializePoint(sess.pointI())...)
	t = append(t, gotrax.SerializePoint(sess.keypairS().Pub.K())...)
	t = append(t, kdfx(usageReceiverPrekeyCompositePHI, 64, phi)...)

	if !m.sigma.verify(sess.clientProfile().PublicKey, s.key.Pub, sess.keypairS().Pub, t) {
		return errors.New("incorrect ring signature")
	}

	return nil
}

func (m *dake1Message) respond(from string, s *GenericServer) (serializable, error) {
	sk := gotrax.GenerateKeypair(s)
	s.session(from).save(sk, m.i, m.instanceTag, m.clientProfile)

	phi := gotrax.AppendData(gotrax.AppendData(nil, []byte(from)), []byte(s.identity))

	t := append([]byte{}, 0x00)
	t = append(t, kdfx(usageInitiatorClientProfile, 64, m.clientProfile.Serialize())...)
	t = append(t, kdfx(usageInitiatorPrekeyCompositeIdentity, 64, s.compositeIdentity())...)
	t = append(t, gotrax.SerializePoint(m.i)...)
	t = append(t, gotrax.SerializePoint(sk.Pub.K())...)
	t = append(t, kdfx(usageInitiatorPrekeyCompositePHI, 64, phi)...)

	sigma, e := generateSignature(s, s.key.Priv, s.key.Pub, m.clientProfile.PublicKey, s.key.Pub, gotrax.CreatePublicKey(m.i, gotrax.Ed448Key), t)
	if e != nil {
		return nil, errors.New("invalid ring signature generation")
	}

	return generateDake2(m.instanceTag, []byte(s.identity), s.key.Pub.K(), sk.Pub.K(), sigma), nil
}

func (m *dake3Message) respond(from string, s *GenericServer) (serializable, error) {
	return s.messageHandler.handleInnerMessage(from, m.message)
}
