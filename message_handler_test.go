package prekeyserver

import (
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
	}
	d1 := generateDake1(sita.instanceTag, sita.clientProfile, gs.key.pub.k)
	_, e := (&otrngMessageHandler{s: gs}).handleMessage("someone@somewhere.org", d1.serialize())
	c.Assert(e, ErrorMatches, "invalid ring signature generation")
}
