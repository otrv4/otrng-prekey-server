package prekeyserver

import (
	"github.com/otrv4/ed448"
	. "gopkg.in/check.v1"
)

func (s *GenericServerSuite) Test_dake3Message_validate_acceptsAValidDake3Message(c *C) {
	serverKey := deriveEDDSAKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        fixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.pub.fingerprint(),
	}
	gs.session("someone@example.org").(*realSession).tag = sita.instanceTag

	phi := []byte("hardcoded phi for now")

	spoint := generateECDHKeypair(gs)
	gs.session("someone@example.org").(*realSession).s = spoint
	gs.session("someone@example.org").(*realSession).i = sita.i.pub.k
	gs.session("someone@example.org").(*realSession).cp = sita.clientProfile

	t := append([]byte{}, 0x01)
	t = append(t, kdfx(usageReceiverClientProfile, 64, sita.clientProfile.serialize())...)
	t = append(t, kdfx(usageReceiverPrekeyCompositeIdentity, 64, gs.compositeIdentity())...)
	t = append(t, serializePoint(sita.i.pub.k)...)
	t = append(t, serializePoint(spoint.pub.k)...)
	t = append(t, kdfx(usageReceiverPrekeyCompositePHI, 64, phi)...)

	sigma, _ := generateSignature(gs, sita.longTerm.priv, sita.longTerm.pub, sita.longTerm.pub, gs.key.pub, spoint.pub, t)

	d3 := generateDake3(sita.instanceTag, sigma, []byte{0x01})
	c.Assert(d3.validate("someone@example.org", gs), IsNil)
}

func (s *GenericServerSuite) Test_dake3Message_validate_checksInstanceTag(c *C) {
	serverKey := deriveEDDSAKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        fixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.pub.fingerprint(),
	}
	gs.session("someone@example.org").(*realSession).tag = sita.instanceTag

	phi := []byte("hardcoded phi for now")

	spoint := generateECDHKeypair(gs)
	gs.session("someone@example.org").(*realSession).s = spoint
	gs.session("someone@example.org").(*realSession).i = sita.i.pub.k
	gs.session("someone@example.org").(*realSession).cp = sita.clientProfile

	t := append([]byte{}, 0x01)
	t = append(t, kdfx(usageReceiverClientProfile, 64, sita.clientProfile.serialize())...)
	t = append(t, kdfx(usageReceiverPrekeyCompositeIdentity, 64, gs.compositeIdentity())...)
	t = append(t, serializePoint(sita.i.pub.k)...)
	t = append(t, serializePoint(spoint.pub.k)...)
	t = append(t, kdfx(usageReceiverPrekeyCompositePHI, 64, phi)...)

	sigma, _ := generateSignature(gs, sita.longTerm.priv, sita.longTerm.pub, sita.longTerm.pub, gs.key.pub, spoint.pub, t)

	d3 := generateDake3(0xBADBADBA, sigma, []byte{0x01})
	c.Assert(d3.validate("someone@example.org", gs), ErrorMatches, "incorrect instance tag")
}

func (s *GenericServerSuite) Test_dake3Message_validate_checksRingSignature(c *C) {
	serverKey := deriveEDDSAKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        fixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.pub.fingerprint(),
	}
	gs.session("someone@example.org").(*realSession).tag = sita.instanceTag

	phi := []byte("hardcoded phi for now")

	spoint := generateECDHKeypair(gs)
	gs.session("someone@example.org").(*realSession).s = spoint
	gs.session("someone@example.org").(*realSession).i = sita.i.pub.k
	gs.session("someone@example.org").(*realSession).cp = sita.clientProfile

	t := append([]byte{}, 0x01)
	t = append(t, kdfx(usageReceiverClientProfile, 64, sita.clientProfile.serialize())...)
	t = append(t, kdfx(usageReceiverPrekeyCompositeIdentity, 64, gs.compositeIdentity())...)
	t = append(t, serializePoint(sita.i.pub.k)...)
	t = append(t, serializePoint(spoint.pub.k)...)
	t = append(t, kdfx(usageReceiverPrekeyCompositePHI, 64, phi)...)

	sigma, _ := generateSignature(gs, sita.longTerm.priv, sita.longTerm.pub, sita.longTerm.pub, gs.key.pub, spoint.pub, t)

	sigma.c1.Add(sigma.c1, ed448.NewScalar([]byte{0x01}))
	d3 := generateDake3(sita.instanceTag, sigma, []byte{0x01})
	c.Assert(d3.validate("someone@example.org", gs), ErrorMatches, "incorrect ring signature")
}

func (s *GenericServerSuite) Test_dake3Message_validate_checksMessage(c *C) {
	serverKey := deriveEDDSAKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        fixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.pub.fingerprint(),
	}
	gs.session("someone@example.org").(*realSession).tag = sita.instanceTag

	phi := []byte("hardcoded phi for now")

	spoint := generateECDHKeypair(gs)
	gs.session("someone@example.org").(*realSession).s = spoint
	gs.session("someone@example.org").(*realSession).i = sita.i.pub.k
	gs.session("someone@example.org").(*realSession).cp = sita.clientProfile

	t := append([]byte{}, 0x01)
	t = append(t, kdfx(usageReceiverClientProfile, 64, sita.clientProfile.serialize())...)
	t = append(t, kdfx(usageReceiverPrekeyCompositeIdentity, 64, gs.compositeIdentity())...)
	t = append(t, serializePoint(sita.i.pub.k)...)
	t = append(t, serializePoint(spoint.pub.k)...)
	t = append(t, kdfx(usageReceiverPrekeyCompositePHI, 64, phi)...)

	sigma, _ := generateSignature(gs, sita.longTerm.priv, sita.longTerm.pub, sita.longTerm.pub, gs.key.pub, spoint.pub, t)

	d3 := generateDake3(sita.instanceTag, sigma, []byte{})
	c.Assert(d3.validate("someone@example.org", gs), ErrorMatches, "incorrect message")
}
