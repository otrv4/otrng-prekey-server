package prekeyserver

import (
	"errors"

	. "gopkg.in/check.v1"
)

func (s *GenericServerSuite) Test_parseMessage_returnsAnErrorForTooShortMessages(c *C) {
	_, e := parseMessage([]byte{})
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("message too short to be a valid message"))

	_, e = parseMessage([]byte{0x01, 0x02})
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("message too short to be a valid message"))
}

func (s *GenericServerSuite) Test_parseMessage_returnsAnErrorForUnknownMessageType(c *C) {
	_, e := parseMessage([]byte{0x00, 0x04, 0x42})
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("unknown message type: 0x42"))
}

func (s *GenericServerSuite) Test_parseMessage_returnsAnErrorForInvalidVersion(c *C) {
	_, e := parseMessage([]byte{0x00, 0x00, 0x01})
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid protocol version"))

	_, e = parseMessage([]byte{0x00, 0x01, 0x01})
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid protocol version"))

	_, e = parseMessage([]byte{0x00, 0x02, 0x01})
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid protocol version"))

	_, e = parseMessage([]byte{0x00, 0x03, 0x01})
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid protocol version"))

	_, e = parseMessage([]byte{0x00, 0x05, 0x01})
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid protocol version"))

	_, e = parseMessage([]byte{0x24, 0x05, 0x01})
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid protocol version"))
}
