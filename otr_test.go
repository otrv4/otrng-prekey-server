package prekeyserver

import (
	"time"

	. "gopkg.in/check.v1"
)

func (s *GenericServerSuite) Test_clientProfile_validate_checksForCorrectInstanceTag(c *C) {
	cp := &clientProfile{
		instanceTag: 0x12345678,
	}
	c.Assert(cp.validate(0x88898888), ErrorMatches, "invalid instance tag in client profile")
}

func (s *GenericServerSuite) Test_clientProfile_validate_validatesACorrectClientProfile(c *C) {
	cp := generateSitaTestData().clientProfile
	c.Assert(cp.validate(sita.instanceTag), IsNil)
}

func (s *GenericServerSuite) Test_clientProfile_validate_checksForCorrectSignature(c *C) {
	cp := generateSitaTestData().clientProfile
	cp.instanceTag = 0xBADBADBA
	c.Assert(cp.validate(0xBADBADBA), ErrorMatches, "invalid signature in client profile")
}

func (s *GenericServerSuite) Test_clientProfile_validate_checksForExpiry(c *C) {
	cp := generateSitaTestData().clientProfile
	cp.expiration = time.Date(2017, 11, 5, 13, 46, 00, 13, time.UTC)
	cp.sig = &eddsaSignature{s: cp.generateSignature(sita.longTerm)}
	c.Assert(cp.validate(sita.instanceTag), ErrorMatches, "client profile has expired")
}

func (s *GenericServerSuite) Test_clientProfile_validate_versionsInclude4(c *C) {
	cp := generateSitaTestData().clientProfile
	cp.versions = []byte{0x03}
	cp.sig = &eddsaSignature{s: cp.generateSignature(sita.longTerm)}
	c.Assert(cp.validate(sita.instanceTag), ErrorMatches, "client profile doesn't support version 4")
}

func (s *GenericServerSuite) Test_prekeyProfile_validate_validatesACorrectPrekeyProfile(c *C) {
	gs := &GenericServer{
		rand:     fixtureRand(),
		sessions: newSessionManager(),
	}
	gs.session("somewhere@example.org").(*realSession).cp = sita.clientProfile
	pp, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	c.Assert(pp.validate(sita.instanceTag, sita.longTerm.pub), IsNil)
}

func (s *GenericServerSuite) Test_prekeyProfile_validate_checksForCorrectInstanceTag(c *C) {
	gs := &GenericServer{
		rand:     fixtureRand(),
		sessions: newSessionManager(),
	}
	gs.session("somewhere@example.org").(*realSession).cp = sita.clientProfile
	pp, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	pp.instanceTag = 0xBADBADBA
	pp.sig = &eddsaSignature{s: pp.generateSignature(sita.longTerm)}
	c.Assert(pp.validate(sita.instanceTag, sita.longTerm.pub), ErrorMatches, "invalid instance tag in prekey profile")
}

func (s *GenericServerSuite) Test_prekeyProfile_validate_checksValidSignature(c *C) {
	gs := &GenericServer{
		rand:     fixtureRand(),
		sessions: newSessionManager(),
	}
	gs.session("somewhere@example.org").(*realSession).cp = sita.clientProfile
	pp, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	pp.sig.s[0] = 0x42
	c.Assert(pp.validate(sita.instanceTag, sita.longTerm.pub), ErrorMatches, "invalid signature in prekey profile")
}

func (s *GenericServerSuite) Test_prekeyProfile_validate_checksForExpiry(c *C) {
	gs := &GenericServer{
		rand:     fixtureRand(),
		sessions: newSessionManager(),
	}
	gs.session("somewhere@example.org").(*realSession).cp = sita.clientProfile
	pp, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	pp.expiration = time.Date(2017, 11, 5, 13, 46, 00, 13, time.UTC)
	pp.sig = &eddsaSignature{s: pp.generateSignature(sita.longTerm)}
	c.Assert(pp.validate(sita.instanceTag, sita.longTerm.pub), ErrorMatches, "prekey profile has expired")
}

func (s *GenericServerSuite) Test_prekeyProfile_validate_checksValidSharedPrekeyPoint(c *C) {
	gs := &GenericServer{
		rand:     fixtureRand(),
		sessions: newSessionManager(),
	}
	gs.session("somewhere@example.org").(*realSession).cp = sita.clientProfile
	pp, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	pp.sharedPrekey = identityPoint
	pp.sig = &eddsaSignature{s: pp.generateSignature(sita.longTerm)}
	c.Assert(pp.validate(sita.instanceTag, sita.longTerm.pub), ErrorMatches, "prekey profile shared prekey is not a valid point")
}

func (s *GenericServerSuite) Test_prekeyMessage_validate_validatesACorrectPrekeyMessage(c *C) {
	gs := &GenericServer{
		rand: fixtureRand(),
	}
	pm, _ := generatePrekeyMessage(gs, sita.instanceTag)
	c.Assert(pm.validate(sita.instanceTag), IsNil)
}

func (s *GenericServerSuite) Test_prekeyMessage_validate_checksInvalidInstanceTag(c *C) {
	gs := &GenericServer{
		rand: fixtureRand(),
	}
	pm, _ := generatePrekeyMessage(gs, 0xBADBADBA)
	c.Assert(pm.validate(sita.instanceTag), ErrorMatches, "invalid instance tag in prekey message")
}

func (s *GenericServerSuite) Test_prekeyMessage_validate_checksInvalidYPoint(c *C) {
	gs := &GenericServer{
		rand: fixtureRand(),
	}
	pm, _ := generatePrekeyMessage(gs, sita.instanceTag)
	pm.y = identityPoint
	c.Assert(pm.validate(sita.instanceTag), ErrorMatches, "prekey profile Y point is not a valid point")
}

func (s *GenericServerSuite) Test_prekeyMessage_validate_checksInvalidBValue(c *C) {
	gs := &GenericServer{
		rand: fixtureRand(),
	}
	pm, _ := generatePrekeyMessage(gs, sita.instanceTag)
	pm.b = []byte{0x00}
	c.Assert(pm.validate(sita.instanceTag), ErrorMatches, "prekey profile B value is not a valid DH group member")
}
