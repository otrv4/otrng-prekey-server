package prekeyserver

import (
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
