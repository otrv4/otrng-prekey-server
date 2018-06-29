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
	c.Assert(e, DeepEquals, errors.New("empty message"))
}

type mockMessageHandler struct {
	receivedFrom    string
	receivedMessage []byte
	toReturnMessage []byte
	toReturnError   error
}

func (m *mockMessageHandler) handleMessage(s *GenericServer, from string, message []byte) ([]byte, error) {
	m.receivedFrom = from
	m.receivedMessage = message
	return m.toReturnMessage, m.toReturnError
}

func (s *GenericServerSuite) Test_Handle_WillPassOnTheIdentityToTheMessageHandler(c *C) {
	m := &mockMessageHandler{}
	gs := &GenericServer{messageHandler: m}
	gs.Handle("myname", "aGksIHRoaXMgaXMgbm90IGEgdmFsaWQgb3RyNCBtZXNzYWdlLCBidXQgc3RpbGwuLi4=.")
	c.Assert(m.receivedFrom, Equals, "myname")
}

func (s *GenericServerSuite) Test_Handle_WillDecodeBase64EncodedMessage(c *C) {
	m := &mockMessageHandler{}
	gs := &GenericServer{messageHandler: m}
	gs.Handle("myname", "aGksIHRoaXMgaXMgbm90IGEgdmFsaWQgb3RyNCBtZXNzYWdlLCBidXQgc3RpbGwuLi4=.")
	c.Assert(m.receivedMessage, DeepEquals, []byte("hi, this is not a valid otr4 message, but still..."))
}

func (s *GenericServerSuite) Test_Handle_AMessageWithoutProperFormatSHhouldGenerateAnError(c *C) {
	gs := &GenericServer{messageHandler: &mockMessageHandler{}}
	_, e := gs.Handle("myname", "aGksIHRoaXMgaXMgbm90IGEgdmFsaWQgb3RyNCBtZXNzYWdlLCBidXQgc3RpbGwuLi4=")
	c.Assert(e, DeepEquals, errors.New("invalid message format - missing ending punctuation"))
}

func (s *GenericServerSuite) Test_Handle_ACorruptedBase64MessageGeneratesAnError(c *C) {
	gs := &GenericServer{messageHandler: &mockMessageHandler{}}
	_, e := gs.Handle("myname", "aGksIHRoaXMgaXMgbm90IGEgdmFsaWQgb3RyNCBtZXNzYWdlLCBidXQgc3RpbGwuLi4.")
	c.Assert(e, DeepEquals, errors.New("invalid message format - corrupted base64 encoding"))
}

func (s *GenericServerSuite) Test_Handle_WillBase64EncodeAndFormatReturnValues(c *C) {
	m := &mockMessageHandler{
		toReturnMessage: []byte("this is our fancy return"),
	}
	gs := &GenericServer{messageHandler: m}
	msgs, _ := gs.Handle("myname", "aGksIHRoaXMgaXMgbm90IGEgdmFsaWQgb3RyNCBtZXNzYWdlLCBidXQgc3RpbGwuLi4=.")
	c.Assert(len(msgs), Equals, 1)
	c.Assert(msgs[0], Equals, "dGhpcyBpcyBvdXIgZmFuY3kgcmV0dXJu.")
}

func (s *GenericServerSuite) Test_Handle_ReturnsAnErrorFromMessageHandler(c *C) {
	m := &mockMessageHandler{
		toReturnError: errors.New("yipii"),
	}
	gs := &GenericServer{messageHandler: m}
	msgs, e := gs.Handle("myname", "aGksIHRoaXMgaXMgbm90IGEgdmFsaWQgb3RyNCBtZXNzYWdlLCBidXQgc3RpbGwuLi4=.")
	c.Assert(msgs, IsNil)
	c.Assert(e, DeepEquals, errors.New("yipii"))
}
