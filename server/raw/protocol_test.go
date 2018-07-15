package main

import (
	"errors"
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type RawServerSuite struct{}

var _ = Suite(&RawServerSuite{})

func (s *RawServerSuite) Test_protocolEncodePacket_encodesTheData(c *C) {
	res := protocolEncodePacket([]byte{0x42, 0x53, 0x11})
	c.Assert(res, DeepEquals, []byte{0x00, 0x03, 0x42, 0x53, 0x11})
}

func (s *RawServerSuite) Test_protocolParseData_willParseDataAndReturnIt(c *C) {
	data := append([]byte{}, 0x00, 0x03)
	data = append(data, []byte("ola")...)
	data = append(data, 0x00, 0x05)
	data = append(data, []byte("abcde")...)
	data = append(data, 0x00, 0x06)
	data = append(data, []byte("arnold")...)
	data = append(data, 0x00, 0x03)
	data = append(data, []byte("123")...)

	res, e := protocolParseData(data)
	c.Assert(e, IsNil)
	c.Assert(res, HasLen, 2)
	c.Assert(res[0].from, Equals, "ola")
	c.Assert(res[0].data, Equals, "abcde")
	c.Assert(res[1].from, Equals, "arnold")
	c.Assert(res[1].data, Equals, "123")
}

func (s *RawServerSuite) Test_protocolParseData_willGenerateErrorIfCantReadLength(c *C) {
	_, e := protocolParseData([]byte{0x00})
	c.Assert(e, ErrorMatches, "can't parse length of from element")
}

func (s *RawServerSuite) Test_protocolParseData_willGenerateErrorIfCantReadFrom(c *C) {
	_, e := protocolParseData([]byte{0x00, 0x03, 0x01})
	c.Assert(e, ErrorMatches, "can't parse from element")
}

func (s *RawServerSuite) Test_protocolParseData_willGenerateErrorIfCantReadLengthOfData(c *C) {
	_, e := protocolParseData([]byte{0x00, 0x01, 0x65, 0x00})
	c.Assert(e, ErrorMatches, "can't parse length of data element")
}

func (s *RawServerSuite) Test_protocolParseData_willGenerateErrorIfCantReadData(c *C) {
	_, e := protocolParseData([]byte{0x00, 0x01, 0x65, 0x00, 0x05, 0x01})
	c.Assert(e, ErrorMatches, "can't parse data element")
}

type mockServer struct {
	ix           int
	receivedFrom []string
	receivedData []string
	returnData   [][]string
	returnError  []error
}

func (ms *mockServer) Handle(from, message string) ([]string, error) {
	currentIx := ms.ix
	ms.ix++
	ms.receivedFrom = append(ms.receivedFrom, from)
	ms.receivedData = append(ms.receivedData, from)
	return ms.returnData[currentIx], ms.returnError[currentIx]
}

func (s *RawServerSuite) Test_protocolHandleData_handsOverDataCorrectlyToTheServer(c *C) {
	data := append([]byte{}, 0x00, 0x03)
	data = append(data, []byte("ola")...)
	data = append(data, 0x00, 0x05)
	data = append(data, []byte("abcde")...)
	data = append(data, 0x00, 0x06)
	data = append(data, []byte("arnold")...)
	data = append(data, 0x00, 0x03)
	data = append(data, []byte("123")...)

	ms := &mockServer{}
	ms.returnData = [][]string{
		[]string{"one", "two"},
		[]string{"three"},
	}
	ms.returnError = []error{nil, nil}
	ret, e := protocolHandleData(data, ms)
	c.Assert(e, IsNil)
	c.Assert(ret, DeepEquals, []byte{
		0x00, 0x03, 0x6f, 0x6e, 0x65,
		0x00, 0x03, 0x74, 0x77, 0x6f,
		0x00, 0x05, 0x74, 0x68, 0x72, 0x65, 0x65,
	})
}

func (s *RawServerSuite) Test_protocolHandleData_willReturnParsingErrors(c *C) {
	_, e := protocolHandleData([]byte{0x00, 0x03}, nil)
	c.Assert(e, ErrorMatches, "can't parse from element")
}

func (s *RawServerSuite) Test_protocolHandleData_willReturnServerErrors(c *C) {
	data := append([]byte{}, 0x00, 0x03)
	data = append(data, []byte("ola")...)
	data = append(data, 0x00, 0x05)
	data = append(data, []byte("abcde")...)

	ms := &mockServer{}
	ms.returnData = [][]string{
		nil,
	}
	ms.returnError = []error{errors.New("something frobbed")}
	_, e := protocolHandleData(data, ms)
	c.Assert(e, ErrorMatches, "something frobbed")
}
