package prekeyserver

import (
	"time"

	"github.com/coyim/gotrax"
	. "gopkg.in/check.v1"
)

func (s *GenericServerSuite) Test_inMemoryStorage_numberStored_returns0ForUnknownUser(c *C) {
	is := &inMemoryStorage{}
	c.Assert(is.numberStored("foo@example.org", 0x11223344), Equals, uint32(0))
}

func (s *GenericServerSuite) Test_inMemoryStorage_numberStored_returnsNumberOfPrekeyMessages(c *C) {
	is := createInMemoryStorage()
	se := is.storageEntryFor("foo@example.org")
	se.prekeyMessages[0x11223344] = []*prekeyMessage{nil, nil}
	c.Assert(is.numberStored("foo@example.org", 0x11223344), Equals, uint32(2))
}

func (s *GenericServerSuite) Test_inMemoryStorage_cleanup_willRemoveExpiredClientProfiles(c *C) {
	is := createInMemoryStorage()

	cp := generateSitaTestData().clientProfile
	cp.Expiration = time.Date(2017, 11, 5, 13, 46, 00, 13, time.UTC)
	cp.Sig = gotrax.CreateEddsaSignature(cp.GenerateSignature(sita.longTerm))

	cp2 := generateSitaTestData().clientProfile
	cp2.InstanceTag = 0x42424242
	cp2.Sig = gotrax.CreateEddsaSignature(cp2.GenerateSignature(sita.longTerm))

	is.storeClientProfile("someone@example.org", cp)
	is.storeClientProfile("someone@example.org", cp2)
	is.storeClientProfile("someoneElse@example.org", sita.clientProfile)
	is.storeClientProfile("someoneThird@example.org", cp)

	is.cleanup()

	c.Assert(is.perUser, HasLen, 2)
	c.Assert(is.perUser["someone@example.org"].clientProfiles, HasLen, 1)
	c.Assert(is.perUser["someoneElse@example.org"].clientProfiles, HasLen, 1)
	c.Assert(is.perUser["someoneThird@example.org"], IsNil)
}

func (s *GenericServerSuite) Test_inMemoryStorage_cleanup_willRemoveExpiredPrekeyProfiles(c *C) {
	gs := &GenericServer{
		rand: gotrax.FixtureRand(),
	}
	is := createInMemoryStorage()

	pp1, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2017, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	pp2, _ := generatePrekeyProfile(gs, 0x42424242, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)

	is.storePrekeyProfile("someone@example.org", pp1)
	is.storePrekeyProfile("someone@example.org", pp2)
	is.storePrekeyProfile("someoneElse@example.org", pp2)
	is.storePrekeyProfile("someoneThird@example.org", pp1)

	is.cleanup()

	c.Assert(is.perUser, HasLen, 2)
	c.Assert(is.perUser["someone@example.org"].prekeyProfiles, HasLen, 1)
	c.Assert(is.perUser["someoneElse@example.org"].prekeyProfiles, HasLen, 1)
	c.Assert(is.perUser["someoneThird@example.org"], IsNil)
}
func (s *GenericServerSuite) Test_inMemoryStorage_cleanup_shouldNotRemoveUserIfThereArePrekeyMessages(c *C) {
	gs := &GenericServer{
		rand: gotrax.FixtureRand(),
	}
	is := createInMemoryStorage()

	pp1, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2017, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	pp2, _ := generatePrekeyProfile(gs, 0x42424242, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)

	pm1, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)

	is.storePrekeyProfile("someone@example.org", pp1)
	is.storePrekeyProfile("someone@example.org", pp2)
	is.storePrekeyProfile("someoneElse@example.org", pp2)
	is.storePrekeyProfile("someoneThird@example.org", pp1)

	is.storePrekeyMessages("someoneThird@example.org", []*prekeyMessage{pm1})

	is.cleanup()

	c.Assert(is.perUser, HasLen, 3)
	c.Assert(is.perUser["someone@example.org"].prekeyProfiles, HasLen, 1)
	c.Assert(is.perUser["someoneElse@example.org"].prekeyProfiles, HasLen, 1)
	c.Assert(is.perUser["someoneThird@example.org"].prekeyProfiles, HasLen, 0)
	c.Assert(is.perUser["someoneThird@example.org"].prekeyMessages, HasLen, 1)
}
