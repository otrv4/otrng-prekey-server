package prekeyserver

import (
	"github.com/otrv4/ed448"
	. "gopkg.in/check.v1"
)

func (s *GenericServerSuite) Test_otrngMessageHandler_handleMessage_errorsOnMessageParsing(c *C) {
	_, e := (&otrngMessageHandler{}).handleMessage("", []byte{0x01, 0x02, 0x03, 0x04})
	c.Assert(e, ErrorMatches, "invalid protocol version")
}

func (s *GenericServerSuite) Test_otrngMessageHandler_handleMessage_errorsOnErrorsFromResponse(c *C) {
	stor := createInMemoryStorage()
	serverKey := deriveKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        fixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.pub.fingerprint(),
		storageImpl: stor,
		sessions:    newSessionManager(),
		rest:        nullRestrictor,
	}
	d1 := generateDake1(sita.instanceTag, sita.clientProfile, gs.key.pub.k)
	_, e := (&otrngMessageHandler{s: gs}).handleMessage("someone@somewhere.org", d1.serialize())
	c.Assert(e, ErrorMatches, "invalid ring signature generation")
}

func (s *GenericServerSuite) Test_otrngMessageHandler_handleMessage_errorsOnRestrictedDake1(c *C) {
	stor := createInMemoryStorage()
	serverKey := deriveKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        fixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.pub.fingerprint(),
		storageImpl: stor,
		sessions:    newSessionManager(),
		rest:        func(string) bool { return true },
	}
	mh := &otrngMessageHandler{s: gs}
	gs.messageHandler = mh

	d1 := generateDake1(sita.instanceTag, sita.clientProfile, sita.i.pub.k)

	_, e := (&otrngMessageHandler{s: gs}).handleMessage("someone@somewhere.org", d1.serialize())
	c.Assert(e, ErrorMatches, "this from-string is restricted for these kinds of messages")
}

func (s *GenericServerSuite) Test_otrngMessageHandler_handleMessage_errorsOnRestrictedDake3(c *C) {
	stor := createInMemoryStorage()
	serverKey := deriveKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        fixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.pub.fingerprint(),
		storageImpl: stor,
		sessions:    newSessionManager(),
		rest:        nullRestrictor,
	}
	mh := &otrngMessageHandler{s: gs}
	gs.messageHandler = mh

	d1 := generateDake1(sita.instanceTag, sita.clientProfile, sita.i.pub.k)
	r, _ := mh.handleMessage("sita@example.org", d1.serialize())
	gs.rest = func(string) bool { return true }
	d2 := dake2Message{}
	d2.deserialize(r)

	phi := appendData(appendData(nil, []byte("sita@example.org")), []byte(gs.identity))

	t := append([]byte{}, 0x01)
	t = append(t, kdfx(usageReceiverClientProfile, 64, sita.clientProfile.serialize())...)
	t = append(t, kdfx(usageReceiverPrekeyCompositeIdentity, 64, gs.compositeIdentity())...)
	t = append(t, serializePoint(sita.i.pub.k)...)
	t = append(t, serializePoint(d2.s)...)
	t = append(t, kdfx(usageReceiverPrekeyCompositePHI, 64, phi)...)

	sigma, _ := generateSignature(gs, sita.longTerm.priv, sita.longTerm.pub, sita.longTerm.pub, gs.key.pub, &publicKey{k: d2.s}, t)
	sk := kdfx(usageSK, skLength, serializePoint(ed448.PointScalarMul(d2.s, sita.i.priv.k)))
	sitaPrekeyMac := kdfx(usagePreMACKey, 64, sk)
	msg := generateStorageInformationRequestMessage(sitaPrekeyMac)

	d3 := generateDake3(sita.instanceTag, sigma, msg.serialize())

	_, e := (&otrngMessageHandler{s: gs}).handleMessage("someone@somewhere.org", d3.serialize())
	c.Assert(e, ErrorMatches, "this from-string is restricted for these kinds of messages")
}
