package prekeyserver

import (
	"github.com/otrv4/ed448"
	"github.com/otrv4/gotrx"
	. "gopkg.in/check.v1"
)

func (s *GenericServerSuite) Test_otrngMessageHandler_handleMessage_errorsOnMessageParsing(c *C) {
	_, e := (&otrngMessageHandler{}).handleMessage("", []byte{0x01, 0x02, 0x03, 0x04})
	c.Assert(e, ErrorMatches, "invalid protocol version")
}

func (s *GenericServerSuite) Test_otrngMessageHandler_handleMessage_errorsOnErrorsFromResponse(c *C) {
	stor := createInMemoryStorage()
	serverKey := gotrx.DeriveKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        gotrx.FixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.Pub.Fingerprint(),
		storageImpl: stor,
		sessions:    newSessionManager(),
		rest:        nullRestrictor,
	}
	d1 := generateDake1(sita.instanceTag, sita.clientProfile, gs.key.Pub.K())
	_, e := (&otrngMessageHandler{s: gs}).handleMessage("someone@somewhere.org", d1.serialize())
	c.Assert(e, ErrorMatches, "invalid ring signature generation")
}

func (s *GenericServerSuite) Test_otrngMessageHandler_handleMessage_errorsOnRestrictedDake1(c *C) {
	stor := createInMemoryStorage()
	serverKey := gotrx.DeriveKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        gotrx.FixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.Pub.Fingerprint(),
		storageImpl: stor,
		sessions:    newSessionManager(),
		rest:        func(string) bool { return true },
	}
	mh := &otrngMessageHandler{s: gs}
	gs.messageHandler = mh

	d1 := generateDake1(sita.instanceTag, sita.clientProfile, sita.i.Pub.K())

	_, e := (&otrngMessageHandler{s: gs}).handleMessage("someone@somewhere.org", d1.serialize())
	c.Assert(e, ErrorMatches, "this from-string is restricted for these kinds of messages")
}

func (s *GenericServerSuite) Test_otrngMessageHandler_handleMessage_errorsOnRestrictedDake3(c *C) {
	stor := createInMemoryStorage()
	serverKey := gotrx.DeriveKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        gotrx.FixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.Pub.Fingerprint(),
		storageImpl: stor,
		sessions:    newSessionManager(),
		rest:        nullRestrictor,
	}
	mh := &otrngMessageHandler{s: gs}
	gs.messageHandler = mh

	d1 := generateDake1(sita.instanceTag, sita.clientProfile, sita.i.Pub.K())
	r, _ := mh.handleMessage("sita@example.org", d1.serialize())
	gs.rest = func(string) bool { return true }
	d2 := dake2Message{}
	d2.deserialize(r)

	phi := gotrx.AppendData(gotrx.AppendData(nil, []byte("sita@example.org")), []byte(gs.identity))

	t := append([]byte{}, 0x01)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverClientProfile, 64, sita.clientProfile.Serialize())...)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverPrekeyCompositeIdentity, 64, gs.compositeIdentity())...)
	t = append(t, gotrx.SerializePoint(sita.i.Pub.K())...)
	t = append(t, gotrx.SerializePoint(d2.s)...)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverPrekeyCompositePHI, 64, phi)...)

	sigma, _ := gotrx.GenerateSignature(gs, sita.longTerm.Priv, sita.longTerm.Pub, sita.longTerm.Pub, gs.key.Pub, gotrx.CreatePublicKey(d2.s, gotrx.Ed448Key), t, gotrx.KdfPrekeyServer, usageAuth)
	sk := gotrx.KdfPrekeyServer(usageSK, skLength, gotrx.SerializePoint(ed448.PointScalarMul(d2.s, sita.i.Priv.K())))
	sitaPrekeyMac := gotrx.KdfPrekeyServer(usagePreMACKey, 64, sk)
	msg := generateStorageInformationRequestMessage(sitaPrekeyMac)

	d3 := generateDake3(sita.instanceTag, sigma, msg.serialize())

	_, e := (&otrngMessageHandler{s: gs}).handleMessage("someone@somewhere.org", d3.serialize())
	c.Assert(e, ErrorMatches, "this from-string is restricted for these kinds of messages")
}
