package prekeyserver

import (
	"errors"
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type GenericServerSuite struct{}

var _ = Suite(&GenericServerSuite{})

func (s *GenericServerSuite) Test_Handle_ReturnsErrorIfGivenEmptyMessage(c *C) {
	gs := &GenericServer{}
	msgs, e := gs.Handle("myname", "")
	c.Assert(msgs, IsNil)
	c.Assert(e, Equals, errors.New("empty message"))
}
