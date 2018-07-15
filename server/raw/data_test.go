package main

import (
	. "gopkg.in/check.v1"
)

func (s *RawServerSuite) Test_appendShort_willAppendTheWord(c *C) {
	res := appendShort(nil, 0x4215)
	c.Assert(res, DeepEquals, []byte{0x42, 0x15})
}

func (s *RawServerSuite) Test_extractShort_willExtractTheShortAndReturnTheRemaining(c *C) {
	d := []byte{0x42, 0x15, 0x11}
	rem, sh, ok := extractShort(d)
	c.Assert(rem, DeepEquals, []byte{0x11})
	c.Assert(ok, Equals, true)
	c.Assert(sh, Equals, uint16(0x4215))
}

func (s *RawServerSuite) Test_extractShort_willFailIfNotEnoughBytesGiven(c *C) {
	_, _, ok := extractShort([]byte{})
	c.Assert(ok, Equals, false)

	_, _, ok = extractShort([]byte{0x01})
	c.Assert(ok, Equals, false)
}

func (s *RawServerSuite) Test_extractFixedData_willExtractTheLengthOfDataAndReturnTheRest(c *C) {
	d := []byte{0x42, 0x15, 0x11}
	rem, sh, ok := extractFixedData(d, 2)
	c.Assert(rem, DeepEquals, []byte{0x11})
	c.Assert(ok, Equals, true)
	c.Assert(sh, DeepEquals, []byte{0x42, 0x15})
}

func (s *RawServerSuite) Test_extractFixedData_willFailIfNotEnoughBytesGiven(c *C) {
	_, _, ok := extractFixedData([]byte{}, 2)
	c.Assert(ok, Equals, false)

	_, _, ok = extractFixedData([]byte{0x01}, 2)
	c.Assert(ok, Equals, false)
}
