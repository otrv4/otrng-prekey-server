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

func (s *GenericServerSuite) Test_Handle_HandlesAFragmentedMessage(c *C) {
	m := &mockMessageHandler{
		toReturnMessage: []byte("this is our fancy return"),
	}

	gs := &GenericServer{messageHandler: m, fragmentations: newFragmentations()}

	msgs, e := gs.Handle("myname", "?OTRP|1234|BEEF|CADE,2,2,dmFsaWQgb3RyNCBtZXNzYWdlLCBidXQgc3RpbGwuLi4=.,")
	c.Assert(e, IsNil)
	c.Assert(len(msgs), Equals, 0)

	msgs, e = gs.Handle("myname", "?OTRP|1234|BEEF|CADE,1,2,aGksIHRoaXMgaXMgbm90IGEg,")
	c.Assert(e, IsNil)
	c.Assert(len(msgs), Equals, 1)
	c.Assert(msgs[0], Equals, "dGhpcyBpcyBvdXIgZmFuY3kgcmV0dXJu.")
}

func (s *GenericServerSuite) Test_Handle_PassesOnAFragmentationError(c *C) {
	m := &mockMessageHandler{
		toReturnMessage: []byte("this is our fancy return"),
	}

	gs := &GenericServer{messageHandler: m, fragmentations: newFragmentations()}
	_, e := gs.Handle("myname", "?OTRP|1234|BEEF|CADE,3,2,aGksIHRoaXMgaXMgbm90IGEg,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))
}

func (s *GenericServerSuite) Test_Handle_WillPotentiallyFragmentReturnValues(c *C) {
	m := &mockMessageHandler{
		toReturnMessage: []byte("this is our fancy return"),
	}
	gs := &GenericServer{messageHandler: m, fragLen: 7, rand: fixtureRand()}
	msgs, _ := gs.Handle("myname", "aGksIHRoaXMgaXMgbm90IGEgdmFsaWQgb3RyNCBtZXNzYWdlLCBidXQgc3RpbGwuLi4=.")
	c.Assert(len(msgs), Equals, 5)
	c.Assert(msgs[0], Equals, "?OTRP|2882382797|BEEF|CADE,1,5,dGhpcyB,")
	c.Assert(msgs[1], Equals, "?OTRP|2882382797|BEEF|CADE,2,5,pcyBvdX,")
	c.Assert(msgs[2], Equals, "?OTRP|2882382797|BEEF|CADE,3,5,IgZmFuY,")
	c.Assert(msgs[3], Equals, "?OTRP|2882382797|BEEF|CADE,4,5,3kgcmV0,")
	c.Assert(msgs[4], Equals, "?OTRP|2882382797|BEEF|CADE,5,5,dXJu.,")
}
