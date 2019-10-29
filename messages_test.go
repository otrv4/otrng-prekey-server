package prekeyserver

import (
	"errors"
	"math/big"
	"time"

	"github.com/otrv4/gotrx"
	. "gopkg.in/check.v1"
)

func (s *GenericServerSuite) Test_parseMessage_returnsAnErrorForTooShortMessages(c *C) {
	_, _, e := parseMessage([]byte{})
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("message too short to be a valid message"))

	_, _, e = parseMessage([]byte{0x01, 0x02})
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("message too short to be a valid message"))
}

func (s *GenericServerSuite) Test_parseMessage_returnsAnErrorForUnknownMessageType(c *C) {
	_, _, e := parseMessage([]byte{0x00, 0x04, 0x42})
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("unknown message type: 0x42"))
}

func (s *GenericServerSuite) Test_parseMessage_returnsAnErrorForInvalidVersion(c *C) {
	_, _, e := parseMessage([]byte{0x00, 0x00, 0x01})
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid protocol version"))

	_, _, e = parseMessage([]byte{0x00, 0x01, 0x01})
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid protocol version"))

	_, _, e = parseMessage([]byte{0x00, 0x02, 0x01})
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid protocol version"))

	_, _, e = parseMessage([]byte{0x00, 0x03, 0x01})
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid protocol version"))

	_, _, e = parseMessage([]byte{0x00, 0x05, 0x01})
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid protocol version"))

	_, _, e = parseMessage([]byte{0x24, 0x05, 0x01})
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid protocol version"))
}

func (s *GenericServerSuite) Test_publicationMessage_validate_willValidateAValidMessage(c *C) {
	sitaSK := []byte{
		0x2a, 0x67, 0xb6, 0x76, 0x27, 0xf9, 0x2d, 0xff,
		0x3b, 0x3f, 0x0, 0xb9, 0x16, 0x8, 0x93, 0x66,
		0xa3, 0x7d, 0x5f, 0x28, 0xb, 0x1d, 0xe4, 0xdd,
		0x4d, 0x69, 0x2b, 0x7c, 0x8d, 0xcf, 0x6f, 0xeb,
		0x59, 0xd5, 0x36, 0x44, 0x61, 0x2c, 0xe1, 0xce,
		0x56, 0x38, 0xf5, 0x31, 0x93, 0xe2, 0x3f, 0x93,
		0x42, 0x5c, 0x2d, 0xbb, 0xe5, 0x4b, 0x90, 0xce,
		0x3f, 0x75, 0x9, 0xed, 0xf4, 0xfc, 0x90, 0x94,
	}
	sitaPrekeyMacK := []byte{
		0x1a, 0x67, 0xb6, 0x76, 0x27, 0xf9, 0x2d, 0xff,
		0x1b, 0x3f, 0x0, 0xb9, 0x16, 0x8, 0x93, 0x66,
		0xb3, 0x7d, 0x5f, 0x28, 0xb, 0x1d, 0xe4, 0xdd,
		0x4d, 0x69, 0x2b, 0x7c, 0x8d, 0xcf, 0x6f, 0xeb,
		0x59, 0xd5, 0x36, 0x44, 0x61, 0x2c, 0xe1, 0xce,
		0x56, 0x38, 0xf5, 0x31, 0x93, 0xe2, 0x3f, 0x93,
		0x42, 0x5c, 0x2d, 0xbb, 0xe5, 0x4b, 0x90, 0xce,
		0x3f, 0x75, 0x9, 0xed, 0xf4, 0xfc, 0x90, 0x94,
	}
	gs := &GenericServer{
		rand:     gotrx.FixtureRand(),
		sessions: newSessionManager(),
	}
	gs.session("somewhere@example.org").(*realSession).tag = sita.instanceTag
	gs.session("somewhere@example.org").(*realSession).storedMac = sitaPrekeyMacK
	gs.session("somewhere@example.org").(*realSession).sk = sitaSK
	gs.session("somewhere@example.org").(*realSession).cp = sita.clientProfile

	pp1, ppk1 := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	pm1, pmk1, pmbpriv1, pmbpub1 := generatePrekeyMessage(gs, sita.instanceTag)
	pm2, pmk2, pmbpriv2, pmbpub2 := generatePrekeyMessage(gs, sita.instanceTag)
	prof1, prof2 := generatePrekeyMessagesProofs(gs, []*gotrx.Keypair{pmk1, pmk2}, []*big.Int{pmbpriv1, pmbpriv2}, []*big.Int{pmbpub1, pmbpub2}, sitaSK)
	prof3 := gemeratePrekeyProfileProof(gs, ppk1, sitaSK)

	msg := generatePublicationMessage(sita.clientProfile, pp1, []*prekeyMessage{pm1, pm2}, prof1, prof2, prof3, sitaPrekeyMacK)
	c.Assert(msg.validate("somewhere@example.org", gs), IsNil)
}

func (s *GenericServerSuite) Test_publicationMessage_validate_failsOnInvalidMac(c *C) {
	sitaSK := []byte{
		0x2a, 0x67, 0xb6, 0x76, 0x27, 0xf9, 0x2d, 0xff,
		0x3b, 0x3f, 0x0, 0xb9, 0x16, 0x8, 0x93, 0x66,
		0xa3, 0x7d, 0x5f, 0x28, 0xb, 0x1d, 0xe4, 0xdd,
		0x4d, 0x69, 0x2b, 0x7c, 0x8d, 0xcf, 0x6f, 0xeb,
		0x59, 0xd5, 0x36, 0x44, 0x61, 0x2c, 0xe1, 0xce,
		0x56, 0x38, 0xf5, 0x31, 0x93, 0xe2, 0x3f, 0x93,
		0x42, 0x5c, 0x2d, 0xbb, 0xe5, 0x4b, 0x90, 0xce,
		0x3f, 0x75, 0x9, 0xed, 0xf4, 0xfc, 0x90, 0x94,
	}
	sitaPrekeyMacK := []byte{
		0xba, 0xdb, 0xad, 0x76, 0x27, 0xf9, 0x2d, 0xff,
		0x1b, 0x3f, 0x0, 0xb9, 0x16, 0x8, 0x93, 0x66,
		0xb3, 0x7d, 0x5f, 0x28, 0xb, 0x1d, 0xe4, 0xdd,
		0x4d, 0x69, 0x2b, 0x7c, 0x8d, 0xcf, 0x6f, 0xeb,
		0x59, 0xd5, 0x36, 0x44, 0x61, 0x2c, 0xe1, 0xce,
		0x56, 0x38, 0xf5, 0x31, 0x93, 0xe2, 0x3f, 0x93,
		0x42, 0x5c, 0x2d, 0xbb, 0xe5, 0x4b, 0x90, 0xce,
		0x3f, 0x75, 0x9, 0xed, 0xf4, 0xfc, 0x90, 0x94,
	}
	gs := &GenericServer{
		rand:     gotrx.FixtureRand(),
		sessions: newSessionManager(),
	}
	gs.session("somewhere@example.org").(*realSession).tag = sita.instanceTag
	gs.session("somewhere@example.org").(*realSession).sk = sitaSK
	gs.session("somewhere@example.org").(*realSession).storedMac = []byte{
		0x1a, 0x67, 0xb6, 0x76, 0x27, 0xf9, 0x2d, 0xff,
		0x1b, 0x3f, 0x0, 0xb9, 0x16, 0x8, 0x93, 0x66,
		0xb3, 0x7d, 0x5f, 0x28, 0xb, 0x1d, 0xe4, 0xdd,
		0x4d, 0x69, 0x2b, 0x7c, 0x8d, 0xcf, 0x6f, 0xeb,
		0x59, 0xd5, 0x36, 0x44, 0x61, 0x2c, 0xe1, 0xce,
		0x56, 0x38, 0xf5, 0x31, 0x93, 0xe2, 0x3f, 0x93,
		0x42, 0x5c, 0x2d, 0xbb, 0xe5, 0x4b, 0x90, 0xce,
		0x3f, 0x75, 0x9, 0xed, 0xf4, 0xfc, 0x90, 0x94,
	}
	gs.session("somewhere@example.org").(*realSession).cp = sita.clientProfile
	pp1, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	pm1, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
	pm2, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
	msg := generatePublicationMessage(sita.clientProfile, pp1, []*prekeyMessage{pm1, pm2}, nil, nil, nil, sitaPrekeyMacK)
	c.Assert(msg.validate("somewhere@example.org", gs), ErrorMatches, "invalid mac for publication message")
}

func (s *GenericServerSuite) Test_publicationMessage_validate_failsOnInvalidClientProfile(c *C) {
	sitaSK := []byte{
		0x2a, 0x67, 0xb6, 0x76, 0x27, 0xf9, 0x2d, 0xff,
		0x3b, 0x3f, 0x0, 0xb9, 0x16, 0x8, 0x93, 0x66,
		0xa3, 0x7d, 0x5f, 0x28, 0xb, 0x1d, 0xe4, 0xdd,
		0x4d, 0x69, 0x2b, 0x7c, 0x8d, 0xcf, 0x6f, 0xeb,
		0x59, 0xd5, 0x36, 0x44, 0x61, 0x2c, 0xe1, 0xce,
		0x56, 0x38, 0xf5, 0x31, 0x93, 0xe2, 0x3f, 0x93,
		0x42, 0x5c, 0x2d, 0xbb, 0xe5, 0x4b, 0x90, 0xce,
		0x3f, 0x75, 0x9, 0xed, 0xf4, 0xfc, 0x90, 0x94,
	}
	sitaPrekeyMacK := []byte{
		0x1a, 0x67, 0xb6, 0x76, 0x27, 0xf9, 0x2d, 0xff,
		0x1b, 0x3f, 0x0, 0xb9, 0x16, 0x8, 0x93, 0x66,
		0xb3, 0x7d, 0x5f, 0x28, 0xb, 0x1d, 0xe4, 0xdd,
		0x4d, 0x69, 0x2b, 0x7c, 0x8d, 0xcf, 0x6f, 0xeb,
		0x59, 0xd5, 0x36, 0x44, 0x61, 0x2c, 0xe1, 0xce,
		0x56, 0x38, 0xf5, 0x31, 0x93, 0xe2, 0x3f, 0x93,
		0x42, 0x5c, 0x2d, 0xbb, 0xe5, 0x4b, 0x90, 0xce,
		0x3f, 0x75, 0x9, 0xed, 0xf4, 0xfc, 0x90, 0x94,
	}
	gs := &GenericServer{
		rand:     gotrx.FixtureRand(),
		sessions: newSessionManager(),
	}
	gs.session("somewhere@example.org").(*realSession).tag = 0xDDDDAAAA
	gs.session("somewhere@example.org").(*realSession).storedMac = sitaPrekeyMacK
	gs.session("somewhere@example.org").(*realSession).sk = sitaSK
	gs.session("somewhere@example.org").(*realSession).cp = sita.clientProfile

	cp := generateSitaTestData().clientProfile
	cp.Expiration = time.Date(2017, 11, 5, 13, 46, 00, 13, time.UTC)
	cp.Sig = gotrx.CreateEddsaSignature(cp.GenerateSignature(sita.longTerm))
	pp1, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	pm1, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
	pm2, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
	msg := generatePublicationMessage(cp, pp1, []*prekeyMessage{pm1, pm2}, nil, nil, nil, sitaPrekeyMacK)
	c.Assert(msg.validate("somewhere@example.org", gs), ErrorMatches, "invalid client profile in publication message")
}

func (s *GenericServerSuite) Test_publicationMessage_validate_failsOnInvalidPrekeyProfile(c *C) {
	sitaSK := []byte{
		0x2a, 0x67, 0xb6, 0x76, 0x27, 0xf9, 0x2d, 0xff,
		0x3b, 0x3f, 0x0, 0xb9, 0x16, 0x8, 0x93, 0x66,
		0xa3, 0x7d, 0x5f, 0x28, 0xb, 0x1d, 0xe4, 0xdd,
		0x4d, 0x69, 0x2b, 0x7c, 0x8d, 0xcf, 0x6f, 0xeb,
		0x59, 0xd5, 0x36, 0x44, 0x61, 0x2c, 0xe1, 0xce,
		0x56, 0x38, 0xf5, 0x31, 0x93, 0xe2, 0x3f, 0x93,
		0x42, 0x5c, 0x2d, 0xbb, 0xe5, 0x4b, 0x90, 0xce,
		0x3f, 0x75, 0x9, 0xed, 0xf4, 0xfc, 0x90, 0x94,
	}
	sitaPrekeyMacK := []byte{
		0x1a, 0x67, 0xb6, 0x76, 0x27, 0xf9, 0x2d, 0xff,
		0x1b, 0x3f, 0x0, 0xb9, 0x16, 0x8, 0x93, 0x66,
		0xb3, 0x7d, 0x5f, 0x28, 0xb, 0x1d, 0xe4, 0xdd,
		0x4d, 0x69, 0x2b, 0x7c, 0x8d, 0xcf, 0x6f, 0xeb,
		0x59, 0xd5, 0x36, 0x44, 0x61, 0x2c, 0xe1, 0xce,
		0x56, 0x38, 0xf5, 0x31, 0x93, 0xe2, 0x3f, 0x93,
		0x42, 0x5c, 0x2d, 0xbb, 0xe5, 0x4b, 0x90, 0xce,
		0x3f, 0x75, 0x9, 0xed, 0xf4, 0xfc, 0x90, 0x94,
	}
	gs := &GenericServer{
		rand:     gotrx.FixtureRand(),
		sessions: newSessionManager(),
	}
	gs.session("somewhere@example.org").(*realSession).tag = sita.instanceTag
	gs.session("somewhere@example.org").(*realSession).storedMac = sitaPrekeyMacK
	gs.session("somewhere@example.org").(*realSession).sk = sitaSK
	gs.session("somewhere@example.org").(*realSession).cp = sita.clientProfile

	pp1, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	pp1.instanceTag = 0xAADDAADD
	pp1.sig = gotrx.CreateEddsaSignature(pp1.generateSignature(sita.longTerm))
	pm1, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
	pm2, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
	msg := generatePublicationMessage(sita.clientProfile, pp1, []*prekeyMessage{pm1, pm2}, nil, nil, nil, sitaPrekeyMacK)
	c.Assert(msg.validate("somewhere@example.org", gs), ErrorMatches, "invalid prekey profile in publication message")
}

func (s *GenericServerSuite) Test_publicationMessage_validate_failsOnInvalidPrekeyMessage(c *C) {
	sitaSK := []byte{
		0x2a, 0x67, 0xb6, 0x76, 0x27, 0xf9, 0x2d, 0xff,
		0x3b, 0x3f, 0x0, 0xb9, 0x16, 0x8, 0x93, 0x66,
		0xa3, 0x7d, 0x5f, 0x28, 0xb, 0x1d, 0xe4, 0xdd,
		0x4d, 0x69, 0x2b, 0x7c, 0x8d, 0xcf, 0x6f, 0xeb,
		0x59, 0xd5, 0x36, 0x44, 0x61, 0x2c, 0xe1, 0xce,
		0x56, 0x38, 0xf5, 0x31, 0x93, 0xe2, 0x3f, 0x93,
		0x42, 0x5c, 0x2d, 0xbb, 0xe5, 0x4b, 0x90, 0xce,
		0x3f, 0x75, 0x9, 0xed, 0xf4, 0xfc, 0x90, 0x94,
	}
	sitaPrekeyMacK := []byte{
		0x1a, 0x67, 0xb6, 0x76, 0x27, 0xf9, 0x2d, 0xff,
		0x1b, 0x3f, 0x0, 0xb9, 0x16, 0x8, 0x93, 0x66,
		0xb3, 0x7d, 0x5f, 0x28, 0xb, 0x1d, 0xe4, 0xdd,
		0x4d, 0x69, 0x2b, 0x7c, 0x8d, 0xcf, 0x6f, 0xeb,
		0x59, 0xd5, 0x36, 0x44, 0x61, 0x2c, 0xe1, 0xce,
		0x56, 0x38, 0xf5, 0x31, 0x93, 0xe2, 0x3f, 0x93,
		0x42, 0x5c, 0x2d, 0xbb, 0xe5, 0x4b, 0x90, 0xce,
		0x3f, 0x75, 0x9, 0xed, 0xf4, 0xfc, 0x90, 0x94,
	}
	gs := &GenericServer{
		rand:     gotrx.FixtureRand(),
		sessions: newSessionManager(),
	}
	gs.session("somewhere@example.org").(*realSession).tag = sita.instanceTag
	gs.session("somewhere@example.org").(*realSession).storedMac = sitaPrekeyMacK
	gs.session("somewhere@example.org").(*realSession).sk = sitaSK
	gs.session("somewhere@example.org").(*realSession).cp = sita.clientProfile

	pp1, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	pm1, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
	pm2, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
	pm2.y = identityPoint
	msg := generatePublicationMessage(sita.clientProfile, pp1, []*prekeyMessage{pm1, pm2}, nil, nil, nil, sitaPrekeyMacK)
	c.Assert(msg.validate("somewhere@example.org", gs), ErrorMatches, "invalid prekey message in publication message")
}

func (s *GenericServerSuite) Test_publicationMessage_validate_failsOnMissingProofs(c *C) {
	sitaSK := []byte{
		0x2a, 0x67, 0xb6, 0x76, 0x27, 0xf9, 0x2d, 0xff,
		0x3b, 0x3f, 0x0, 0xb9, 0x16, 0x8, 0x93, 0x66,
		0xa3, 0x7d, 0x5f, 0x28, 0xb, 0x1d, 0xe4, 0xdd,
		0x4d, 0x69, 0x2b, 0x7c, 0x8d, 0xcf, 0x6f, 0xeb,
		0x59, 0xd5, 0x36, 0x44, 0x61, 0x2c, 0xe1, 0xce,
		0x56, 0x38, 0xf5, 0x31, 0x93, 0xe2, 0x3f, 0x93,
		0x42, 0x5c, 0x2d, 0xbb, 0xe5, 0x4b, 0x90, 0xce,
		0x3f, 0x75, 0x9, 0xed, 0xf4, 0xfc, 0x90, 0x94,
	}
	sitaPrekeyMacK := []byte{
		0x1a, 0x67, 0xb6, 0x76, 0x27, 0xf9, 0x2d, 0xff,
		0x1b, 0x3f, 0x0, 0xb9, 0x16, 0x8, 0x93, 0x66,
		0xb3, 0x7d, 0x5f, 0x28, 0xb, 0x1d, 0xe4, 0xdd,
		0x4d, 0x69, 0x2b, 0x7c, 0x8d, 0xcf, 0x6f, 0xeb,
		0x59, 0xd5, 0x36, 0x44, 0x61, 0x2c, 0xe1, 0xce,
		0x56, 0x38, 0xf5, 0x31, 0x93, 0xe2, 0x3f, 0x93,
		0x42, 0x5c, 0x2d, 0xbb, 0xe5, 0x4b, 0x90, 0xce,
		0x3f, 0x75, 0x9, 0xed, 0xf4, 0xfc, 0x90, 0x94,
	}
	gs := &GenericServer{
		rand:     gotrx.FixtureRand(),
		sessions: newSessionManager(),
	}
	gs.session("somewhere@example.org").(*realSession).tag = sita.instanceTag
	gs.session("somewhere@example.org").(*realSession).storedMac = sitaPrekeyMacK
	gs.session("somewhere@example.org").(*realSession).sk = sitaSK
	gs.session("somewhere@example.org").(*realSession).cp = sita.clientProfile

	pp1, ppk1 := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	pm1, pmk1, pmbpriv1, pmbpub1 := generatePrekeyMessage(gs, sita.instanceTag)
	pm2, pmk2, pmbpriv2, pmbpub2 := generatePrekeyMessage(gs, sita.instanceTag)
	prof1, prof2 := generatePrekeyMessagesProofs(gs, []*gotrx.Keypair{pmk1, pmk2}, []*big.Int{pmbpriv1, pmbpriv2}, []*big.Int{pmbpub1, pmbpub2}, sitaSK)
	prof3 := gemeratePrekeyProfileProof(gs, ppk1, sitaSK)

	msg := generatePublicationMessage(sita.clientProfile, pp1, []*prekeyMessage{pm1, pm2}, nil, prof2, prof3, sitaPrekeyMacK)
	c.Assert(msg.validate("somewhere@example.org", gs), ErrorMatches, "missing proof for prekey messages y key")

	msg = generatePublicationMessage(sita.clientProfile, pp1, []*prekeyMessage{pm1, pm2}, prof1, nil, prof3, sitaPrekeyMacK)
	c.Assert(msg.validate("somewhere@example.org", gs), ErrorMatches, "missing proof for prekey messages b key")

	msg = generatePublicationMessage(sita.clientProfile, pp1, []*prekeyMessage{pm1, pm2}, prof1, prof2, nil, sitaPrekeyMacK)
	c.Assert(msg.validate("somewhere@example.org", gs), ErrorMatches, "missing proof for prekey profile shared prekey")
}

func (s *GenericServerSuite) Test_publicationMessage_validate_failsOnInvalidProofs(c *C) {
	sitaSK := []byte{
		0x2a, 0x67, 0xb6, 0x76, 0x27, 0xf9, 0x2d, 0xff,
		0x3b, 0x3f, 0x0, 0xb9, 0x16, 0x8, 0x93, 0x66,
		0xa3, 0x7d, 0x5f, 0x28, 0xb, 0x1d, 0xe4, 0xdd,
		0x4d, 0x69, 0x2b, 0x7c, 0x8d, 0xcf, 0x6f, 0xeb,
		0x59, 0xd5, 0x36, 0x44, 0x61, 0x2c, 0xe1, 0xce,
		0x56, 0x38, 0xf5, 0x31, 0x93, 0xe2, 0x3f, 0x93,
		0x42, 0x5c, 0x2d, 0xbb, 0xe5, 0x4b, 0x90, 0xce,
		0x3f, 0x75, 0x9, 0xed, 0xf4, 0xfc, 0x90, 0x94,
	}
	sitaPrekeyMacK := []byte{
		0x1a, 0x67, 0xb6, 0x76, 0x27, 0xf9, 0x2d, 0xff,
		0x1b, 0x3f, 0x0, 0xb9, 0x16, 0x8, 0x93, 0x66,
		0xb3, 0x7d, 0x5f, 0x28, 0xb, 0x1d, 0xe4, 0xdd,
		0x4d, 0x69, 0x2b, 0x7c, 0x8d, 0xcf, 0x6f, 0xeb,
		0x59, 0xd5, 0x36, 0x44, 0x61, 0x2c, 0xe1, 0xce,
		0x56, 0x38, 0xf5, 0x31, 0x93, 0xe2, 0x3f, 0x93,
		0x42, 0x5c, 0x2d, 0xbb, 0xe5, 0x4b, 0x90, 0xce,
		0x3f, 0x75, 0x9, 0xed, 0xf4, 0xfc, 0x90, 0x94,
	}
	gs := &GenericServer{
		rand:     gotrx.FixtureRand(),
		sessions: newSessionManager(),
	}
	gs.session("somewhere@example.org").(*realSession).tag = sita.instanceTag
	gs.session("somewhere@example.org").(*realSession).storedMac = sitaPrekeyMacK
	gs.session("somewhere@example.org").(*realSession).sk = sitaSK
	gs.session("somewhere@example.org").(*realSession).cp = sita.clientProfile

	pp1, ppk1 := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	pm1, pmk1, pmbpriv1, pmbpub1 := generatePrekeyMessage(gs, sita.instanceTag)
	pm2, pmk2, pmbpriv2, pmbpub2 := generatePrekeyMessage(gs, sita.instanceTag)
	prof1, prof2 := generatePrekeyMessagesProofs(gs, []*gotrx.Keypair{pmk1, pmk2}, []*big.Int{pmbpriv1, pmbpriv2}, []*big.Int{pmbpub1, pmbpub2}, sitaSK)
	prof3 := gemeratePrekeyProfileProof(gs, ppk1, sitaSK)

	prof1c := append([]byte{}, prof1.c...)
	prof2c := append([]byte{}, prof2.c...)
	prof3c := append([]byte{}, prof3.c...)

	prof1.c[0] = 0xBA
	msg := generatePublicationMessage(sita.clientProfile, pp1, []*prekeyMessage{pm1, pm2}, prof1, prof2, prof3, sitaPrekeyMacK)
	c.Assert(msg.validate("somewhere@example.org", gs), ErrorMatches, "incorrect proof for prekey messages y key")
	prof1.c[0] = prof1c[0]

	prof2.c[0] = 0xBA
	msg = generatePublicationMessage(sita.clientProfile, pp1, []*prekeyMessage{pm1, pm2}, prof1, prof2, prof3, sitaPrekeyMacK)
	c.Assert(msg.validate("somewhere@example.org", gs), ErrorMatches, "incorrect proof for prekey messages b key")
	prof2.c[0] = prof2c[0]

	prof3.c[0] = 0xBA
	msg = generatePublicationMessage(sita.clientProfile, pp1, []*prekeyMessage{pm1, pm2}, prof1, prof2, prof3, sitaPrekeyMacK)
	c.Assert(msg.validate("somewhere@example.org", gs), ErrorMatches, "incorrect proof for prekey profile shared prekey")
	prof3.c[0] = prof3c[0]
}

func (s *GenericServerSuite) Test_ensembleRetrievalQueryMessage_validate_willValidateAValidMessage(c *C) {
	retM := &ensembleRetrievalQueryMessage{
		instanceTag: 0x12445511,
		identity:    "sita@example.org",
		versions:    []byte{0x04},
	}

	c.Assert(retM.validate("bla@example.org", nil), IsNil)
}

func (s *GenericServerSuite) Test_publicationMessage_respond_willRemoveTheSession(c *C) {
	stor := createInMemoryStorage()
	sitaPrekeyMacK := []byte{
		0x1a, 0x67, 0xb6, 0x76, 0x27, 0xf9, 0x2d, 0xff,
		0x1b, 0x3f, 0x0, 0xb9, 0x16, 0x8, 0x93, 0x66,
		0xb3, 0x7d, 0x5f, 0x28, 0xb, 0x1d, 0xe4, 0xdd,
		0x4d, 0x69, 0x2b, 0x7c, 0x8d, 0xcf, 0x6f, 0xeb,
		0x59, 0xd5, 0x36, 0x44, 0x61, 0x2c, 0xe1, 0xce,
		0x56, 0x38, 0xf5, 0x31, 0x93, 0xe2, 0x3f, 0x93,
		0x42, 0x5c, 0x2d, 0xbb, 0xe5, 0x4b, 0x90, 0xce,
		0x3f, 0x75, 0x9, 0xed, 0xf4, 0xfc, 0x90, 0x94,
	}
	gs := &GenericServer{
		rand:        gotrx.FixtureRand(),
		storageImpl: stor,
		sessions:    newSessionManager(),
	}
	gs.session("somewhere@example.org").(*realSession).tag = sita.instanceTag
	gs.session("somewhere@example.org").(*realSession).storedMac = sitaPrekeyMacK

	m := &publicationMessage{
		clientProfile:  sita.clientProfile,
		prekeyProfile:  nil,
		prekeyMessages: []*prekeyMessage{},
	}
	m.respond("somewhere@example.org", gs)
	c.Assert(gs.hasSession("somewhere@example.org"), Equals, false)
}

func (s *GenericServerSuite) Test_generatePrekeyMessagesProofs_returnsNilForEmptyKeys(c *C) {
	r1, r2 := generatePrekeyMessagesProofs(nil, nil, nil, nil, nil)
	c.Assert(r1, IsNil)
	c.Assert(r2, IsNil)
}

func (s *GenericServerSuite) Test_gemeratePrekeyProfileProof_returnsNilForEmptyKey(c *C) {
	r1 := gemeratePrekeyProfileProof(nil, nil, nil)
	c.Assert(r1, IsNil)
}
