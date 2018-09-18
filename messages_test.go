package prekeyserver

import (
	"errors"
	"time"

	"github.com/coyim/gotrax"
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
		rand:     gotrax.FixtureRand(),
		sessions: newSessionManager(),
	}
	gs.session("somewhere@example.org").(*realSession).tag = sita.instanceTag
	gs.session("somewhere@example.org").(*realSession).storedMac = sitaPrekeyMacK
	gs.session("somewhere@example.org").(*realSession).cp = sita.clientProfile

	pp1, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	pm1, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
	pm2, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
	msg := generatePublicationMessage(sita.clientProfile, pp1, []*prekeyMessage{pm1, pm2}, nil, nil, nil, sitaPrekeyMacK)
	c.Assert(msg.validate("somewhere@example.org", gs), IsNil)
}

func (s *GenericServerSuite) Test_publicationMessage_validate_failsOnInvalidMac(c *C) {
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
		rand:     gotrax.FixtureRand(),
		sessions: newSessionManager(),
	}
	gs.session("somewhere@example.org").(*realSession).tag = sita.instanceTag
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
		rand:     gotrax.FixtureRand(),
		sessions: newSessionManager(),
	}
	gs.session("somewhere@example.org").(*realSession).tag = 0xDDDDAAAA
	gs.session("somewhere@example.org").(*realSession).storedMac = sitaPrekeyMacK
	gs.session("somewhere@example.org").(*realSession).cp = sita.clientProfile

	cp := generateSitaTestData().clientProfile
	cp.Expiration = time.Date(2017, 11, 5, 13, 46, 00, 13, time.UTC)
	cp.Sig = gotrax.CreateEddsaSignature(cp.GenerateSignature(sita.longTerm))
	pp1, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	pm1, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
	pm2, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
	msg := generatePublicationMessage(cp, pp1, []*prekeyMessage{pm1, pm2}, nil, nil, nil, sitaPrekeyMacK)
	c.Assert(msg.validate("somewhere@example.org", gs), ErrorMatches, "invalid client profile in publication message")
}

func (s *GenericServerSuite) Test_publicationMessage_validate_failsOnInvalidPrekeyProfile(c *C) {
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
		rand:     gotrax.FixtureRand(),
		sessions: newSessionManager(),
	}
	gs.session("somewhere@example.org").(*realSession).tag = sita.instanceTag
	gs.session("somewhere@example.org").(*realSession).storedMac = sitaPrekeyMacK
	gs.session("somewhere@example.org").(*realSession).cp = sita.clientProfile

	pp1, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	pp1.instanceTag = 0xAADDAADD
	pp1.sig = gotrax.CreateEddsaSignature(pp1.generateSignature(sita.longTerm))
	pm1, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
	pm2, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
	msg := generatePublicationMessage(sita.clientProfile, pp1, []*prekeyMessage{pm1, pm2}, nil, nil, nil, sitaPrekeyMacK)
	c.Assert(msg.validate("somewhere@example.org", gs), ErrorMatches, "invalid prekey profile in publication message")
}

func (s *GenericServerSuite) Test_publicationMessage_validate_failsOnInvalidPrekeyMessage(c *C) {
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
		rand:     gotrax.FixtureRand(),
		sessions: newSessionManager(),
	}
	gs.session("somewhere@example.org").(*realSession).tag = sita.instanceTag
	gs.session("somewhere@example.org").(*realSession).storedMac = sitaPrekeyMacK
	gs.session("somewhere@example.org").(*realSession).cp = sita.clientProfile

	pp1, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	pm1, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
	pm2, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
	pm2.y = identityPoint
	msg := generatePublicationMessage(sita.clientProfile, pp1, []*prekeyMessage{pm1, pm2}, nil, nil, nil, sitaPrekeyMacK)
	c.Assert(msg.validate("somewhere@example.org", gs), ErrorMatches, "invalid prekey message in publication message")
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
		rand:        gotrax.FixtureRand(),
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
