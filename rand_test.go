package prekeyserver

import (
	"crypto/rand"

	. "gopkg.in/check.v1"
)

func (s *GenericServerSuite) Test_GenericServer_randReader_returnsRandIfExists(c *C) {
	gs := &GenericServer{}
	fr := fixtureRand()
	gs.rand = fr
	c.Assert(gs.randReader(), Equals, fr)
}

func (s *GenericServerSuite) Test_GenericServer_randReader_returnsRandReaderOtherwise(c *C) {
	gs := &GenericServer{}
	c.Assert(gs.randReader(), Equals, rand.Reader)
}
