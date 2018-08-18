package prekeyserver

import (
	"crypto/rand"

	"github.com/coyim/gotrax"
	. "gopkg.in/check.v1"
)

func (s *GenericServerSuite) Test_GenericServer_RandReader_returnsRandIfExists(c *C) {
	gs := &GenericServer{}
	fr := gotrax.FixtureRand()
	gs.rand = fr
	c.Assert(gs.RandReader(), Equals, fr)
}

func (s *GenericServerSuite) Test_GenericServer_RandReader_returnsRandReaderOtherwise(c *C) {
	gs := &GenericServer{}
	c.Assert(gs.RandReader(), Equals, rand.Reader)
}
