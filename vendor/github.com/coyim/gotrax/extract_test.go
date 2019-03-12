package gotrax

import (
	"time"

	. "gopkg.in/check.v1"
)

func (s *GotraxSuite) Test_ExtractWord_ExtractsAllTheBytes(c *C) {
	d := []byte{0x12, 0x14, 0x15, 0x17}
	_, result, _ := ExtractWord(d)
	c.Assert(result, Equals, uint32(0x12141517))
}

func (s *GotraxSuite) Test_ExtractWord_ExtractsWithError(c *C) {
	d := []byte{0x12, 0x14, 0x15}
	_, result, ok := ExtractWord(d)
	c.Assert(result, Equals, uint32(0))
	c.Assert(ok, Equals, false)
}

func (s *GotraxSuite) Test_ExtractShort_ExtractsAllTheBytes(c *C) {
	d := []byte{0x12, 0x14}
	_, result, ok := ExtractShort(d)
	c.Assert(result, Equals, uint16(0x1214))
	c.Assert(ok, Equals, true)
}

func (s *GotraxSuite) Test_ExtractShort_isNotOKIfThereIsNotEnoughData(c *C) {
	d := []byte{0x12}
	_, result, ok := ExtractShort(d)
	c.Assert(result, Equals, uint16(0))
	c.Assert(ok, Equals, false)
}

func (s *GotraxSuite) Test_ExtractData_ExtractsFromStartIndex(c *C) {
	d := []byte{0x13, 0x54, 0x00, 0x00, 0x00, 0x05, 0x55, 0x12, 0x04, 0x8A, 0x00}
	index, result, ok := ExtractData(d[2:])
	c.Assert(result, DeepEquals, []byte{0x55, 0x12, 0x04, 0x8A, 0x00})
	c.Assert(index, DeepEquals, []byte{})
	c.Assert(ok, Equals, true)
}

func (s *GotraxSuite) Test_ExtractData_returnsNotOKIfThereIsntEnoughBytesForTheLength(c *C) {
	d := []byte{0x13, 0x54, 0x00}
	_, _, ok := ExtractData(d)
	c.Assert(ok, Equals, false)
}

func (s *GotraxSuite) Test_ExtractData_returnsNotOKIfThereArentEnoughBytes(c *C) {
	d := []byte{0x00, 0x00, 0x00, 0x02, 0x01}
	_, _, ok := ExtractData(d)
	c.Assert(ok, Equals, false)
}

func (s *GotraxSuite) Test_ExtractMPI_returnsNotOKIfThereIsNotEnoughBytesForLength(c *C) {
	d := []byte{0x00, 0x00, 0x01}
	_, _, ok := ExtractMPI(d)
	c.Assert(ok, Equals, false)
}

func (s *GotraxSuite) Test_ExtractMPI_returnsNotOKIfThereIsNotEnoughBytesForTheMPI(c *C) {
	d := []byte{0x00, 0x00, 0x00, 0x02, 0x01}
	_, _, ok := ExtractMPI(d)
	c.Assert(ok, Equals, false)
}

func (s *GotraxSuite) Test_ExtractMPIs_returnsNotOKIfThereIsNotEnoughBytesForLength(c *C) {
	d := []byte{0x00, 0x00, 0x01}
	_, _, ok := ExtractMPIs(d)
	c.Assert(ok, Equals, false)
}

func (s *GotraxSuite) Test_ExtractMPIs_returnsNotOKIfOneOfTheMPIsInsideIsNotValid(c *C) {
	d := []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01}
	_, _, ok := ExtractMPIs(d)
	c.Assert(ok, Equals, false)
}

func (s *GotraxSuite) Test_ExtractMPIs_returnsNotOKIfThereAreNotEnoughMPIs(c *C) {
	d := []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x01}
	_, _, ok := ExtractMPIs(d)
	c.Assert(ok, Equals, false)
}

func (s *GotraxSuite) Test_ExtractMPIs_returnsOKIfAnMPIIsReadCorrectly(c *C) {
	d := []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01}
	_, _, ok := ExtractMPIs(d)
	c.Assert(ok, Equals, true)
}

func (s *GotraxSuite) Test_ExtractByte_ReturnsFalseIfNotEnoughData(c *C) {
	a, b, ok := ExtractByte([]byte{})
	c.Assert(ok, Equals, false)
	c.Assert(a, IsNil)
	c.Assert(b, Equals, byte(0))
}

func (s *GotraxSuite) Test_ExtractByte_ReturnsTheRestAndTheByte(c *C) {
	a, b, ok := ExtractByte([]byte{0x42, 0x55, 0x18})
	c.Assert(ok, Equals, true)
	c.Assert(a, DeepEquals, []byte{0x55, 0x18})
	c.Assert(b, Equals, byte(0x42))
}

func (s *GotraxSuite) Test_ExtractLong_ReturnsFalseIfNotEnoughData(c *C) {
	a, b, ok := ExtractLong([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07})
	c.Assert(ok, Equals, false)
	c.Assert(a, IsNil)
	c.Assert(b, Equals, uint64(0))
}

func (s *GotraxSuite) Test_ExtractLong_ReturnsTheRestAndTheValue(c *C) {
	a, b, ok := ExtractLong([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xA0, 0xDD})
	c.Assert(ok, Equals, true)
	c.Assert(a, DeepEquals, []byte{0x09, 0xA0, 0xDD})
	c.Assert(b, Equals, uint64(0x0102030405060708))
}

func (s *GotraxSuite) Test_ExtractTime_ReturnsFalseIfNotEnoughData(c *C) {
	a, b, ok := ExtractTime([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07})
	c.Assert(ok, Equals, false)
	c.Assert(a, IsNil)
	c.Assert(b, DeepEquals, time.Time{})
}

func (s *GotraxSuite) Test_ExtractTime_ReturnsTheRestAndTheValue(c *C) {
	a, b, ok := ExtractTime([]byte{0x00, 0x00, 0x00, 0x00, 0x6e, 0xb0, 0x41, 0x18, 0xFF, 0x0FD, 0x0A})
	c.Assert(ok, Equals, true)
	c.Assert(a, DeepEquals, []byte{0xFF, 0xFD, 0x0A})
	tt := time.Date(2028, 11, 5, 13, 46, 0, 0, time.UTC)
	c.Assert(b, DeepEquals, tt)
}

func (s *GotraxSuite) Test_ExtractFixedData_ReturnsFalseIfNotEnough(c *C) {
	a, b, ok := ExtractFixedData([]byte{0x01, 0x02}, 3)
	c.Assert(ok, Equals, false)
	c.Assert(a, IsNil)
	c.Assert(b, IsNil)
}

func (s *GotraxSuite) Test_ExtractFixedData_ReturnsTrueAndTheRest(c *C) {
	a, b, ok := ExtractFixedData([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, 3)
	c.Assert(ok, Equals, true)
	c.Assert(a, DeepEquals, []byte{0x04, 0x05, 0x06, 0x07})
	c.Assert(b, DeepEquals, []byte{0x01, 0x02, 0x03})
}
