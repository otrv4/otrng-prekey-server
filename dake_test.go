package prekeyserver

import (
	"github.com/coyim/gotrax"
	"github.com/otrv4/ed448"
	. "gopkg.in/check.v1"
)

func (s *GenericServerSuite) Test_dake3Message_validate_acceptsAValidDake3Message(c *C) {
	serverKey := gotrax.DeriveKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        gotrax.FixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.Pub.Fingerprint(),
		sessions:    newSessionManager(),
	}
	gs.session("someone@example.org").(*realSession).tag = sita.instanceTag

	phi := gotrax.AppendData(gotrax.AppendData(nil, []byte("someone@example.org")), []byte(gs.identity))

	spoint := gotrax.GenerateKeypair(gs)
	gs.session("someone@example.org").(*realSession).s = spoint
	gs.session("someone@example.org").(*realSession).i = sita.i.Pub.K()
	gs.session("someone@example.org").(*realSession).cp = sita.clientProfile

	t := append([]byte{}, 0x01)
	t = append(t, kdfx(usageReceiverClientProfile, 64, sita.clientProfile.Serialize())...)
	t = append(t, kdfx(usageReceiverPrekeyCompositeIdentity, 64, gs.compositeIdentity())...)
	t = append(t, gotrax.SerializePoint(sita.i.Pub.K())...)
	t = append(t, gotrax.SerializePoint(spoint.Pub.K())...)
	t = append(t, kdfx(usageReceiverPrekeyCompositePHI, 64, phi)...)

	sigma, _ := generateSignature(gs, sita.longTerm.Priv, sita.longTerm.Pub, sita.longTerm.Pub, gs.key.Pub, spoint.Pub, t)

	d3 := generateDake3(sita.instanceTag, sigma, []byte{0x01})
	c.Assert(d3.validate("someone@example.org", gs), IsNil)
}

func (s *GenericServerSuite) Test_dake3Message_validate_checksInstanceTag(c *C) {
	serverKey := gotrax.DeriveKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        gotrax.FixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.Pub.Fingerprint(),
		sessions:    newSessionManager(),
	}
	gs.session("someone@example.org").(*realSession).tag = sita.instanceTag

	phi := gotrax.AppendData(gotrax.AppendData(nil, []byte("someone@example.org")), []byte(gs.identity))

	spoint := gotrax.GenerateKeypair(gs)
	gs.session("someone@example.org").(*realSession).s = spoint
	gs.session("someone@example.org").(*realSession).i = sita.i.Pub.K()
	gs.session("someone@example.org").(*realSession).cp = sita.clientProfile

	t := append([]byte{}, 0x01)
	t = append(t, kdfx(usageReceiverClientProfile, 64, sita.clientProfile.Serialize())...)
	t = append(t, kdfx(usageReceiverPrekeyCompositeIdentity, 64, gs.compositeIdentity())...)
	t = append(t, gotrax.SerializePoint(sita.i.Pub.K())...)
	t = append(t, gotrax.SerializePoint(spoint.Pub.K())...)
	t = append(t, kdfx(usageReceiverPrekeyCompositePHI, 64, phi)...)

	sigma, _ := generateSignature(gs, sita.longTerm.Priv, sita.longTerm.Pub, sita.longTerm.Pub, gs.key.Pub, spoint.Pub, t)

	d3 := generateDake3(0xBADBADBA, sigma, []byte{0x01})
	c.Assert(d3.validate("someone@example.org", gs), ErrorMatches, "incorrect instance tag")
}

func (s *GenericServerSuite) Test_dake3Message_validate_checksRingSignature(c *C) {
	serverKey := gotrax.DeriveKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        gotrax.FixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.Pub.Fingerprint(),
		sessions:    newSessionManager(),
	}
	gs.session("someone@example.org").(*realSession).tag = sita.instanceTag

	phi := gotrax.AppendData(gotrax.AppendData(nil, []byte("someone@example.org")), []byte(gs.identity))

	spoint := gotrax.GenerateKeypair(gs)
	gs.session("someone@example.org").(*realSession).s = spoint
	gs.session("someone@example.org").(*realSession).i = sita.i.Pub.K()
	gs.session("someone@example.org").(*realSession).cp = sita.clientProfile

	t := append([]byte{}, 0x01)
	t = append(t, kdfx(usageReceiverClientProfile, 64, sita.clientProfile.Serialize())...)
	t = append(t, kdfx(usageReceiverPrekeyCompositeIdentity, 64, gs.compositeIdentity())...)
	t = append(t, gotrax.SerializePoint(sita.i.Pub.K())...)
	t = append(t, gotrax.SerializePoint(spoint.Pub.K())...)
	t = append(t, kdfx(usageReceiverPrekeyCompositePHI, 64, phi)...)

	sigma, _ := generateSignature(gs, sita.longTerm.Priv, sita.longTerm.Pub, sita.longTerm.Pub, gs.key.Pub, spoint.Pub, t)

	sigma.c1.Add(sigma.c1, ed448.NewScalar([]byte{0x01}))
	d3 := generateDake3(sita.instanceTag, sigma, []byte{0x01})
	c.Assert(d3.validate("someone@example.org", gs), ErrorMatches, "incorrect ring signature")
}

func (s *GenericServerSuite) Test_dake3Message_validate_checksMessage(c *C) {
	serverKey := gotrax.DeriveKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        gotrax.FixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.Pub.Fingerprint(),
		sessions:    newSessionManager(),
	}
	gs.session("someone@example.org").(*realSession).tag = sita.instanceTag

	phi := gotrax.AppendData(gotrax.AppendData(nil, []byte("someone@example.org")), []byte(gs.identity))

	spoint := gotrax.GenerateKeypair(gs)
	gs.session("someone@example.org").(*realSession).s = spoint
	gs.session("someone@example.org").(*realSession).i = sita.i.Pub.K()
	gs.session("someone@example.org").(*realSession).cp = sita.clientProfile

	t := append([]byte{}, 0x01)
	t = append(t, kdfx(usageReceiverClientProfile, 64, sita.clientProfile.Serialize())...)
	t = append(t, kdfx(usageReceiverPrekeyCompositeIdentity, 64, gs.compositeIdentity())...)
	t = append(t, gotrax.SerializePoint(sita.i.Pub.K())...)
	t = append(t, gotrax.SerializePoint(spoint.Pub.K())...)
	t = append(t, kdfx(usageReceiverPrekeyCompositePHI, 64, phi)...)

	sigma, _ := generateSignature(gs, sita.longTerm.Priv, sita.longTerm.Pub, sita.longTerm.Pub, gs.key.Pub, spoint.Pub, t)

	d3 := generateDake3(sita.instanceTag, sigma, []byte{})
	c.Assert(d3.validate("someone@example.org", gs), ErrorMatches, "incorrect message")
}

func (s *GenericServerSuite) Test_dake3Message_respond_shouldFailOnInvalidRingSignatureGeneration(c *C) {
	stor := createInMemoryStorage()
	serverKey := gotrax.DeriveKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        gotrax.FixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.Pub.Fingerprint(),
		storageImpl: stor,
		sessions:    newSessionManager(),
	}
	d1 := generateDake1(sita.instanceTag, sita.clientProfile, gs.key.Pub.K())

	_, e := d1.respond("someone@example.org", gs)
	c.Assert(e, ErrorMatches, "invalid ring signature generation")
}
