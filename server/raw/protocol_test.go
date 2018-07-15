package main

import (
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type RawServerSuite struct{}

var _ = Suite(&RawServerSuite{})

func (s *RawServerSuite) Test_appendShort_willAppendTheWord(c *C) {
	res := appendShort(nil, 0x4215)
	c.Assert(res, DeepEquals, []byte{0x42, 0x15})
}
