package prekeyserver

import (
	"github.com/otrv4/ed448"
	"github.com/otrv4/gotrx"
	. "gopkg.in/check.v1"
)

func (s *GenericServerSuite) Test_dake3Message_validate_acceptsAValidDake3Message(c *C) {
	serverKey := gotrx.DeriveKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        gotrx.FixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.Pub.Fingerprint(),
		sessions:    newSessionManager(),
	}
	gs.session("someone@example.org").(*realSession).tag = sita.instanceTag

	phi := gotrx.AppendData(gotrx.AppendData(nil, []byte("someone@example.org")), []byte(gs.identity))

	spoint := gotrx.GenerateKeypair(gs)
	gs.session("someone@example.org").(*realSession).s = spoint
	gs.session("someone@example.org").(*realSession).i = sita.i.Pub.K()
	gs.session("someone@example.org").(*realSession).cp = sita.clientProfile

	t := append([]byte{}, 0x01)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverClientProfile, 64, sita.clientProfile.Serialize())...)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverPrekeyCompositeIdentity, 64, gs.compositeIdentity())...)
	t = append(t, gotrx.SerializePoint(sita.i.Pub.K())...)
	t = append(t, gotrx.SerializePoint(spoint.Pub.K())...)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverPrekeyCompositePHI, 64, phi)...)

	sigma, _ := gotrx.GenerateSignature(gs, sita.longTerm.Priv, sita.longTerm.Pub, sita.longTerm.Pub, gs.key.Pub, spoint.Pub, t, gotrx.KdfPrekeyServer, usageAuth)

	d3 := generateDake3(sita.instanceTag, sigma, []byte{0x01})
	c.Assert(d3.validate("someone@example.org", gs), IsNil)
}

func (s *GenericServerSuite) Test_dake3Message_validate_checksInstanceTag(c *C) {
	serverKey := gotrx.DeriveKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        gotrx.FixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.Pub.Fingerprint(),
		sessions:    newSessionManager(),
	}
	gs.session("someone@example.org").(*realSession).tag = sita.instanceTag

	phi := gotrx.AppendData(gotrx.AppendData(nil, []byte("someone@example.org")), []byte(gs.identity))

	spoint := gotrx.GenerateKeypair(gs)
	gs.session("someone@example.org").(*realSession).s = spoint
	gs.session("someone@example.org").(*realSession).i = sita.i.Pub.K()
	gs.session("someone@example.org").(*realSession).cp = sita.clientProfile

	t := append([]byte{}, 0x01)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverClientProfile, 64, sita.clientProfile.Serialize())...)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverPrekeyCompositeIdentity, 64, gs.compositeIdentity())...)
	t = append(t, gotrx.SerializePoint(sita.i.Pub.K())...)
	t = append(t, gotrx.SerializePoint(spoint.Pub.K())...)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverPrekeyCompositePHI, 64, phi)...)

	sigma, _ := gotrx.GenerateSignature(gs, sita.longTerm.Priv, sita.longTerm.Pub, sita.longTerm.Pub, gs.key.Pub, spoint.Pub, t, gotrx.KdfPrekeyServer, usageAuth)

	d3 := generateDake3(0xBADBADBA, sigma, []byte{0x01})
	c.Assert(d3.validate("someone@example.org", gs), ErrorMatches, "incorrect instance tag")
}

func (s *GenericServerSuite) Test_dake3Message_validate_checksRingSignature(c *C) {
	serverKey := gotrx.DeriveKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        gotrx.FixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.Pub.Fingerprint(),
		sessions:    newSessionManager(),
	}
	gs.session("someone@example.org").(*realSession).tag = sita.instanceTag

	phi := gotrx.AppendData(gotrx.AppendData(nil, []byte("someone@example.org")), []byte(gs.identity))

	spoint := gotrx.GenerateKeypair(gs)
	gs.session("someone@example.org").(*realSession).s = spoint
	gs.session("someone@example.org").(*realSession).i = sita.i.Pub.K()
	gs.session("someone@example.org").(*realSession).cp = sita.clientProfile

	t := append([]byte{}, 0x01)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverClientProfile, 64, sita.clientProfile.Serialize())...)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverPrekeyCompositeIdentity, 64, gs.compositeIdentity())...)
	t = append(t, gotrx.SerializePoint(sita.i.Pub.K())...)
	t = append(t, gotrx.SerializePoint(spoint.Pub.K())...)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverPrekeyCompositePHI, 64, phi)...)

	sigma, _ := gotrx.GenerateSignature(gs, sita.longTerm.Priv, sita.longTerm.Pub, sita.longTerm.Pub, gs.key.Pub, spoint.Pub, t, gotrx.KdfPrekeyServer, usageAuth)

	sigma.C1.Add(sigma.C1, ed448.NewScalar([]byte{0x01}))
	d3 := generateDake3(sita.instanceTag, sigma, []byte{0x01})
	c.Assert(d3.validate("someone@example.org", gs), ErrorMatches, "incorrect ring signature")
}

func (s *GenericServerSuite) Test_dake3Message_validate_checksMessage(c *C) {
	serverKey := gotrx.DeriveKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        gotrx.FixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.Pub.Fingerprint(),
		sessions:    newSessionManager(),
	}
	gs.session("someone@example.org").(*realSession).tag = sita.instanceTag

	phi := gotrx.AppendData(gotrx.AppendData(nil, []byte("someone@example.org")), []byte(gs.identity))

	spoint := gotrx.GenerateKeypair(gs)
	gs.session("someone@example.org").(*realSession).s = spoint
	gs.session("someone@example.org").(*realSession).i = sita.i.Pub.K()
	gs.session("someone@example.org").(*realSession).cp = sita.clientProfile

	t := append([]byte{}, 0x01)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverClientProfile, 64, sita.clientProfile.Serialize())...)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverPrekeyCompositeIdentity, 64, gs.compositeIdentity())...)
	t = append(t, gotrx.SerializePoint(sita.i.Pub.K())...)
	t = append(t, gotrx.SerializePoint(spoint.Pub.K())...)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverPrekeyCompositePHI, 64, phi)...)

	sigma, _ := gotrx.GenerateSignature(gs, sita.longTerm.Priv, sita.longTerm.Pub, sita.longTerm.Pub, gs.key.Pub, spoint.Pub, t, gotrx.KdfPrekeyServer, usageAuth)

	d3 := generateDake3(sita.instanceTag, sigma, []byte{})
	c.Assert(d3.validate("someone@example.org", gs), ErrorMatches, "incorrect message")
}

func (s *GenericServerSuite) Test_dake3Message_respond_shouldFailOnInvalidRingSignatureGeneration(c *C) {
	stor := createInMemoryStorage()
	serverKey := gotrx.DeriveKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        gotrx.FixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.Pub.Fingerprint(),
		storageImpl: stor,
		sessions:    newSessionManager(),
	}
	d1 := generateDake1(sita.instanceTag, sita.clientProfile, gs.key.Pub.K())

	_, e := d1.respond("someone@example.org", gs)
	c.Assert(e, ErrorMatches, "invalid ring signature generation")
}
