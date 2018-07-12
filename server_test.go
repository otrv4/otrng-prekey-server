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

func (m *mockMessageHandler) handleMessage(from string, message []byte) ([]byte, error) {
	m.receivedFrom = from
	m.receivedMessage = message
	return m.toReturnMessage, m.toReturnError
}

func (m *mockMessageHandler) handleInnerMessage(from string, message []byte) (serializable, error) {
	return nil, nil
}

func (s *GenericServerSuite) Test_Handle_WillPassOnTheIdentityToTheMessageHandler(c *C) {
	gs := &GenericServer{}
	m := &mockMessageHandler{}
	gs.messageHandler = m
	gs.Handle("myname", "aGksIHRoaXMgaXMgbm90IGEgdmFsaWQgb3RyNCBtZXNzYWdlLCBidXQgc3RpbGwuLi4=.")
	c.Assert(m.receivedFrom, Equals, "myname")
}

func (s *GenericServerSuite) Test_Handle_WillDecodeBase64EncodedMessage(c *C) {
	gs := &GenericServer{}
	m := &mockMessageHandler{}
	gs.messageHandler = m
	gs.Handle("myname", "aGksIHRoaXMgaXMgbm90IGEgdmFsaWQgb3RyNCBtZXNzYWdlLCBidXQgc3RpbGwuLi4=.")
	c.Assert(m.receivedMessage, DeepEquals, []byte("hi, this is not a valid otr4 message, but still..."))
}

func (s *GenericServerSuite) Test_Handle_AMessageWithoutProperFormatSHhouldGenerateAnError(c *C) {
	gs := &GenericServer{}
	m := &mockMessageHandler{}
	gs.messageHandler = m
	_, e := gs.Handle("myname", "aGksIHRoaXMgaXMgbm90IGEgdmFsaWQgb3RyNCBtZXNzYWdlLCBidXQgc3RpbGwuLi4=")
	c.Assert(e, DeepEquals, errors.New("invalid message format - missing ending punctuation"))
}

func (s *GenericServerSuite) Test_Handle_ACorruptedBase64MessageGeneratesAnError(c *C) {
	gs := &GenericServer{}
	m := &mockMessageHandler{}
	gs.messageHandler = m
	_, e := gs.Handle("myname", "aGksIHRoaXMgaXMgbm90IGEgdmFsaWQgb3RyNCBtZXNzYWdlLCBidXQgc3RpbGwuLi4.")
	c.Assert(e, DeepEquals, errors.New("invalid message format - corrupted base64 encoding"))
}

func (s *GenericServerSuite) Test_Handle_WillBase64EncodeAndFormatReturnValues(c *C) {
	gs := &GenericServer{}
	m := &mockMessageHandler{
		toReturnMessage: []byte("this is our fancy return"),
	}
	gs.messageHandler = m
	msgs, _ := gs.Handle("myname", "aGksIHRoaXMgaXMgbm90IGEgdmFsaWQgb3RyNCBtZXNzYWdlLCBidXQgc3RpbGwuLi4=.")
	c.Assert(len(msgs), Equals, 1)
	c.Assert(msgs[0], Equals, "dGhpcyBpcyBvdXIgZmFuY3kgcmV0dXJu.")
}

func (s *GenericServerSuite) Test_Handle_ReturnsAnErrorFromMessageHandler(c *C) {
	gs := &GenericServer{}
	m := &mockMessageHandler{
		toReturnError: errors.New("yipii"),
	}
	gs.messageHandler = m
	msgs, e := gs.Handle("myname", "aGksIHRoaXMgaXMgbm90IGEgdmFsaWQgb3RyNCBtZXNzYWdlLCBidXQgc3RpbGwuLi4=.")
	c.Assert(msgs, IsNil)
	c.Assert(e, DeepEquals, errors.New("yipii"))
}

func (s *GenericServerSuite) Test_Handle_HandlesAFragmentedMessage(c *C) {
	gs := &GenericServer{fragmentations: newFragmentations()}
	m := &mockMessageHandler{
		toReturnMessage: []byte("this is our fancy return"),
	}
	gs.messageHandler = m

	msgs, e := gs.Handle("myname", "?OTRP|1234|BEEF|CADE,2,2,dmFsaWQgb3RyNCBtZXNzYWdlLCBidXQgc3RpbGwuLi4=.,")
	c.Assert(e, IsNil)
	c.Assert(len(msgs), Equals, 0)

	msgs, e = gs.Handle("myname", "?OTRP|1234|BEEF|CADE,1,2,aGksIHRoaXMgaXMgbm90IGEg,")
	c.Assert(e, IsNil)
	c.Assert(len(msgs), Equals, 1)
	c.Assert(msgs[0], Equals, "dGhpcyBpcyBvdXIgZmFuY3kgcmV0dXJu.")
}

func (s *GenericServerSuite) Test_Handle_PassesOnAFragmentationError(c *C) {
	gs := &GenericServer{fragmentations: newFragmentations()}
	m := &mockMessageHandler{
		toReturnMessage: []byte("this is our fancy return"),
	}
	gs.messageHandler = m
	_, e := gs.Handle("myname", "?OTRP|1234|BEEF|CADE,3,2,aGksIHRoaXMgaXMgbm90IGEg,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))
}

func (s *GenericServerSuite) Test_Handle_WillPotentiallyFragmentReturnValues(c *C) {
	gs := &GenericServer{fragLen: 54, rand: fixtureRand()}
	m := &mockMessageHandler{
		toReturnMessage: []byte("this is our fancy return"),
	}
	gs.messageHandler = m
	msgs, _ := gs.Handle("myname", "aGksIHRoaXMgaXMgbm90IGEgdmFsaWQgb3RyNCBtZXNzYWdlLCBidXQgc3RpbGwuLi4=.")
	c.Assert(msgs, HasLen, 5)
	c.Assert(msgs[0], Equals, "?OTRP|2882382797|BEEF|CADE,1,5,dGhpcyB,")
	c.Assert(msgs[1], Equals, "?OTRP|2882382797|BEEF|CADE,2,5,pcyBvdX,")
	c.Assert(msgs[2], Equals, "?OTRP|2882382797|BEEF|CADE,3,5,IgZmFuY,")
	c.Assert(msgs[3], Equals, "?OTRP|2882382797|BEEF|CADE,4,5,3kgcmV0,")
	c.Assert(msgs[4], Equals, "?OTRP|2882382797|BEEF|CADE,5,5,dXJu.,")
}

func (s *GenericServerSuite) Test_handleMessage_panicsWhenNoMessageHandlerIsConfigured(c *C) {
	gs := &GenericServer{fragLen: 7, rand: fixtureRand()}
	c.Assert(func() { gs.handleMessage("foo@example.org", nil) }, PanicMatches, "programmer error, missing message handler")
}
