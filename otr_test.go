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
