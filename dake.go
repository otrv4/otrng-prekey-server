package prekeyserver

import "github.com/twstrike/ed448"

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

func (m *dake1Message) validate() error {
	// TODO: implement
	//  Validate the Client Profile, as defined in Validating a Client Profile section of the OTRv4 specification.
	// 	Verify that the point I received is on curve Ed448. See Verifying that a point is on the curve section of the OTRv4 specification for details.
	return nil
}

func (m *dake1Message) respond(s *GenericServer) (serializable, error) {
	// Obviously we need to save this somewhere for this to work.
	// TODO: for later
	sk := generateECDHKeypair(s)

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
