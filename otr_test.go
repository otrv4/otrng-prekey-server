package prekeyserver

import (
	"math/big"
	"time"

	"github.com/otrv4/gotrx"
	. "gopkg.in/check.v1"
)

func (s *GenericServerSuite) Test_prekeyProfile_validate_validatesACorrectPrekeyProfile(c *C) {
	gs := &GenericServer{
		rand:     gotrx.FixtureRand(),
		sessions: newSessionManager(),
	}
	gs.session("somewhere@example.org").(*realSession).cp = sita.clientProfile
	pp, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	c.Assert(pp.validate(sita.instanceTag, sita.longTerm.Pub), IsNil)
}

func (s *GenericServerSuite) Test_prekeyProfile_validate_checksForCorrectInstanceTag(c *C) {
	gs := &GenericServer{
		rand:     gotrx.FixtureRand(),
		sessions: newSessionManager(),
	}
	gs.session("somewhere@example.org").(*realSession).cp = sita.clientProfile
	pp, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	pp.instanceTag = 0xBADBADBA
	pp.sig = gotrx.CreateEddsaSignature(pp.generateSignature(sita.longTerm))
	c.Assert(pp.validate(sita.instanceTag, sita.longTerm.Pub), ErrorMatches, "invalid instance tag in prekey profile")
}

func (s *GenericServerSuite) Test_prekeyProfile_validate_checksValidSignature(c *C) {
	gs := &GenericServer{
		rand:     gotrx.FixtureRand(),
		sessions: newSessionManager(),
	}
	gs.session("somewhere@example.org").(*realSession).cp = sita.clientProfile
	pp, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	v := pp.sig.S()
	v[0] = 0x42
	pp.sig = gotrx.CreateEddsaSignature(v)
	c.Assert(pp.validate(sita.instanceTag, sita.longTerm.Pub), ErrorMatches, "invalid signature in prekey profile")
}

func (s *GenericServerSuite) Test_prekeyProfile_validate_checksForExpiry(c *C) {
	gs := &GenericServer{
		rand:     gotrx.FixtureRand(),
		sessions: newSessionManager(),
	}
	gs.session("somewhere@example.org").(*realSession).cp = sita.clientProfile
	pp, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	pp.expiration = time.Date(2017, 11, 5, 13, 46, 00, 13, time.UTC)
	pp.sig = gotrx.CreateEddsaSignature(pp.generateSignature(sita.longTerm))
	c.Assert(pp.validate(sita.instanceTag, sita.longTerm.Pub), ErrorMatches, "prekey profile has expired")
}

func (s *GenericServerSuite) Test_prekeyProfile_validate_checksValidSharedPrekeyPoint(c *C) {
	gs := &GenericServer{
		rand:     gotrx.FixtureRand(),
		sessions: newSessionManager(),
	}
	gs.session("somewhere@example.org").(*realSession).cp = sita.clientProfile
	pp, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	pp.sharedPrekey = gotrx.CreatePublicKey(identityPoint, gotrx.Ed448Key)
	pp.sig = gotrx.CreateEddsaSignature(pp.generateSignature(sita.longTerm))
	c.Assert(pp.validate(sita.instanceTag, sita.longTerm.Pub), ErrorMatches, "prekey profile shared prekey is not a valid point")
}

func (s *GenericServerSuite) Test_prekeyMessage_validate_validatesACorrectPrekeyMessage(c *C) {
	gs := &GenericServer{
		rand: gotrx.FixtureRand(),
	}
	pm, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
	c.Assert(pm.validate(sita.instanceTag), IsNil)
}

func (s *GenericServerSuite) Test_prekeyMessage_validate_checksInvalidInstanceTag(c *C) {
	gs := &GenericServer{
		rand: gotrx.FixtureRand(),
	}
	pm, _, _, _ := generatePrekeyMessage(gs, 0xBADBADBA)
	c.Assert(pm.validate(sita.instanceTag), ErrorMatches, "invalid instance tag in prekey message")
}

func (s *GenericServerSuite) Test_prekeyMessage_validate_checksInvalidYPoint(c *C) {
	gs := &GenericServer{
		rand: gotrx.FixtureRand(),
	}
	pm, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
	pm.y = identityPoint
	c.Assert(pm.validate(sita.instanceTag), ErrorMatches, "prekey profile Y point is not a valid point")
}

func (s *GenericServerSuite) Test_prekeyMessage_validate_checksInvalidBValue(c *C) {
	gs := &GenericServer{
		rand: gotrx.FixtureRand(),
	}
	pm, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
	pm.b = new(big.Int).SetBytes([]byte{0x00})
	c.Assert(pm.validate(sita.instanceTag), ErrorMatches, "prekey profile B value is not a valid DH group member")
}
