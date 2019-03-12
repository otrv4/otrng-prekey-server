package gotrax

import (
	"math/big"
	"time"

	. "gopkg.in/check.v1"
)

func (s *GotraxSuite) Test_ClientProfile_Validate_checksForCorrectInstanceTag(c *C) {
	cp := &ClientProfile{
		InstanceTag: 0x12345678,
	}
	c.Assert(cp.Validate(0x88898888), ErrorMatches, "invalid instance tag in client profile")
}

func (s *GotraxSuite) Test_ClientProfile_Validate_validatesACorrectClientProfile(c *C) {
	cp := generateSitaTestData().clientProfile
	c.Assert(cp.Validate(sita.instanceTag), IsNil)
}

func (s *GotraxSuite) Test_ClientProfile_Validate_checksForCorrectSignature(c *C) {
	cp := generateSitaTestData().clientProfile
	cp.InstanceTag = 0xBADBADBA
	c.Assert(cp.Validate(0xBADBADBA), ErrorMatches, "invalid signature in client profile")
}

func (s *GotraxSuite) Test_ClientProfile_Validate_checksForExpiry(c *C) {
	cp := generateSitaTestData().clientProfile
	cp.Expiration = time.Date(2017, 11, 5, 13, 46, 00, 13, time.UTC)
	cp.Sig = &EddsaSignature{s: cp.GenerateSignature(sita.longTerm)}
	c.Assert(cp.Validate(sita.instanceTag), ErrorMatches, "client profile has expired")
}

func (s *GotraxSuite) Test_ClientProfile_Validate_checksForPublicKeyPresence(c *C) {
	cp := generateSitaTestData().clientProfile
	cp.PublicKey = nil
	c.Assert(cp.Validate(sita.instanceTag), ErrorMatches, "missing public key in client profile")
}

func (s *GotraxSuite) Test_ClientProfile_Validate_checksForForgingKeyPresence(c *C) {
	cp := generateSitaTestData().clientProfile
	cp.ForgingKey = nil
	c.Assert(cp.Validate(sita.instanceTag), ErrorMatches, "missing forging key in client profile")
}

func (s *GotraxSuite) Test_ClientProfile_Validate_checksForSignaturePresence(c *C) {
	cp := generateSitaTestData().clientProfile
	cp.Sig = nil
	c.Assert(cp.Validate(sita.instanceTag), ErrorMatches, "missing signature in client profile")
}

func (s *GotraxSuite) Test_ClientProfile_Validate_versionsInclude4(c *C) {
	cp := generateSitaTestData().clientProfile
	cp.Versions = []byte{0x03}
	cp.Sig = &EddsaSignature{s: cp.GenerateSignature(sita.longTerm)}
	c.Assert(cp.Validate(sita.instanceTag), ErrorMatches, "client profile doesn't support version 4")
}

func (s *GotraxSuite) Test_ClientProfile_Equals_returnsTrueIfTheyAreEqual(c *C) {
	cp1 := generateSitaTestData().clientProfile
	cp2 := generateSitaTestData().clientProfile
	c.Assert(cp1.Equals(cp2), Equals, true)
	c.Assert(cp2.Equals(cp1), Equals, true)
	cp1.Versions = []byte{0x03}
	c.Assert(cp1.Equals(cp2), Equals, false)
	c.Assert(cp2.Equals(cp1), Equals, false)
}

func (s *GotraxSuite) Test_ClientProfile_HasExpired_returnsWhetherItsExpired(c *C) {
	cp := &ClientProfile{
		Expiration: time.Date(2028, 11, 5, 13, 46, 00, 13, time.UTC),
	}
	c.Assert(cp.HasExpired(), Equals, false)

	cp.Expiration = time.Date(2017, 11, 5, 13, 46, 00, 13, time.UTC)
	c.Assert(cp.HasExpired(), Equals, true)
}

func (s *GotraxSuite) Test_PrekeyProfile_Validate_validatesACorrectPrekeyProfile(c *C) {
	gs := ReaderIntoWithRandom(FixtureRand())
	pp, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	c.Assert(pp.Validate(sita.instanceTag, sita.longTerm.Pub), IsNil)
}

func (s *GotraxSuite) Test_PrekeyProfile_Validate_checksForCorrectInstanceTag(c *C) {
	gs := ReaderIntoWithRandom(FixtureRand())
	pp, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	pp.InstanceTag = 0xBADBADBA
	pp.Sig = CreateEddsaSignature(pp.GenerateSignature(sita.longTerm))
	c.Assert(pp.Validate(sita.instanceTag, sita.longTerm.Pub), ErrorMatches, "invalid instance tag in prekey profile")
}

func (s *GotraxSuite) Test_PrekeyProfile_Validate_checksValidSignature(c *C) {
	gs := ReaderIntoWithRandom(FixtureRand())
	pp, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	v := pp.Sig.s
	v[0] = 0x42
	pp.Sig = CreateEddsaSignature(v)
	c.Assert(pp.Validate(sita.instanceTag, sita.longTerm.Pub), ErrorMatches, "invalid signature in prekey profile")
}

func (s *GotraxSuite) Test_PrekeyProfile_Validate_checksForExpiry(c *C) {
	gs := ReaderIntoWithRandom(FixtureRand())
	pp, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	pp.Expiration = time.Date(2017, 11, 5, 13, 46, 00, 13, time.UTC)
	pp.Sig = CreateEddsaSignature(pp.GenerateSignature(sita.longTerm))
	c.Assert(pp.Validate(sita.instanceTag, sita.longTerm.Pub), ErrorMatches, "prekey profile has expired")
}

func (s *GotraxSuite) Test_PrekeyProfile_Validate_checksValidSharedPrekeyPoint(c *C) {
	gs := ReaderIntoWithRandom(FixtureRand())
	pp, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	pp.SharedPrekey = CreatePublicKey(IdentityPoint, Ed448Key)
	pp.Sig = CreateEddsaSignature(pp.GenerateSignature(sita.longTerm))
	c.Assert(pp.Validate(sita.instanceTag, sita.longTerm.Pub), ErrorMatches, "prekey profile shared prekey is not a valid point")
}

func (s *GotraxSuite) Test_PrekeyProfile_Equals_work(c *C) {
	gs := ReaderIntoWithRandom(FixtureRand())
	pp, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	pp2, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 47, 00, 13, time.UTC), sita.longTerm)
	c.Assert(pp.Equals(pp), Equals, true)
	c.Assert(pp.Equals(pp2), Equals, false)
	c.Assert(pp2.Equals(pp2), Equals, true)
}

func (s *GotraxSuite) Test_PrekeyMessage_Validate_validatesACorrectPrekeyMessage(c *C) {
	gs := ReaderIntoWithRandom(FixtureRand())
	pm, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
	c.Assert(pm.Validate(sita.instanceTag), IsNil)
}

func (s *GotraxSuite) Test_PrekeyMessage_Validate_checksInvalidInstanceTag(c *C) {
	gs := ReaderIntoWithRandom(FixtureRand())
	pm, _, _, _ := generatePrekeyMessage(gs, 0xBADBADBA)
	c.Assert(pm.Validate(sita.instanceTag), ErrorMatches, "invalid instance tag in prekey message")
}

func (s *GotraxSuite) Test_PrekeyMessage_Validate_checksInvalidYPoint(c *C) {
	gs := ReaderIntoWithRandom(FixtureRand())
	pm, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
	pm.Y = IdentityPoint
	c.Assert(pm.Validate(sita.instanceTag), ErrorMatches, "prekey profile Y point is not a valid point")
}

func (s *GotraxSuite) Test_PrekeyMessage_Validate_checksInvalidBValue(c *C) {
	gs := ReaderIntoWithRandom(FixtureRand())
	pm, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
	pm.B = new(big.Int).SetBytes([]byte{0x00})
	c.Assert(pm.Validate(sita.instanceTag), ErrorMatches, "prekey profile B value is not a valid DH group member")
}

func (s *GotraxSuite) Test_PrekeyMessage_Equals_works(c *C) {
	gs := ReaderIntoWithRandom(FixtureRand())
	pm, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
	pm2, _, _, _ := generatePrekeyMessage(gs, 0x4243)
	c.Assert(pm.Equals(pm), Equals, true)
	c.Assert(pm.Equals(pm2), Equals, false)
	c.Assert(pm2.Equals(pm2), Equals, true)
}
