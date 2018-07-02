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

func (s *GenericServerSuite) Test_noPrekeyEnsemblesMessage_shouldSerializeCorrectly(c *C) {
	m := &noPrekeyEnsemblesMessage{}
	m.instanceTag = 0x4253112D
	m.message = "no prekeys, sorry very sorry"
	expected := []byte{
		// version
		0x00, 0x04,

		// message type
		0x11,

		// instance tag
		0x42, 0x53, 0x11, 0x2D,

		// message
		0x00, 0x00, 0x00, 0x1C, 0x6E, 0x6F, 0x20, 0x70,
		0x72, 0x65, 0x6B, 0x65, 0x79, 0x73, 0x2C, 0x20,
		0x73, 0x6F, 0x72, 0x72, 0x79, 0x20, 0x76, 0x65,
		0x72, 0x79, 0x20, 0x73, 0x6F, 0x72, 0x72, 0x79,
	}

	c.Assert(m.serialize(), DeepEquals, expected)
}

func (s *GenericServerSuite) Test_noPrekeyEnsemblesMessage_shouldDeserializeCorrectly(c *C) {
	m := &noPrekeyEnsemblesMessage{}
	_, ok := m.deserialize([]byte{
		// version
		0x00, 0x04,

		// message type
		0x11,

		// instance tag
		0x42, 0x53, 0x11, 0x2D,

		// message
		0x00, 0x00, 0x00, 0x1C, 0x6E, 0x6F, 0x20, 0x70,
		0x72, 0x65, 0x6B, 0x65, 0x79, 0x73, 0x2C, 0x20,
		0x73, 0x6F, 0x72, 0x72, 0x79, 0x20, 0x76, 0x65,
		0x72, 0x79, 0x20, 0x73, 0x6F, 0x72, 0x72, 0x79,
	})
	c.Assert(ok, Equals, true)
	c.Assert(m.instanceTag, Equals, uint32(0x4253112D))
	c.Assert(m.message, DeepEquals, "no prekeys, sorry very sorry")
}

func (s *GenericServerSuite) Test_ensembleRetrievalQueryMessage_shouldSerializeCorrectly(c *C) {
	m := &ensembleRetrievalQueryMessage{}
	m.instanceTag = 0x4253112E
	m.identity = "foobar@blarg.com/foo"
	m.versions = []byte{0x05, 0x42}
	expected := []byte{
		// version
		0x00, 0x04,

		// message type
		0x09,

		// instance tag
		0x42, 0x53, 0x11, 0x2E,

		// identity
		0x00, 0x00, 0x00, 0x14, 0x66, 0x6f, 0x6f, 0x62,
		0x61, 0x72, 0x40, 0x62, 0x6c, 0x61, 0x72, 0x67,
		0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x66, 0x6f, 0x6f,

		// versions
		0x00, 0x00, 0x00, 0x02,
		0x05, 0x42,
	}

	c.Assert(m.serialize(), DeepEquals, expected)
}

func (s *GenericServerSuite) Test_ensembleRetrievalQueryMessage_shouldDeserializeCorrectly(c *C) {
	m := &ensembleRetrievalQueryMessage{}
	_, ok := m.deserialize([]byte{
		// version
		0x00, 0x04,

		// message type
		0x09,

		// instance tag
		0x42, 0x53, 0x11, 0x2E,

		// identity
		0x00, 0x00, 0x00, 0x14, 0x66, 0x6f, 0x6f, 0x62,
		0x61, 0x72, 0x40, 0x62, 0x6c, 0x61, 0x72, 0x67,
		0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x66, 0x6f, 0x6f,

		// versions
		0x00, 0x00, 0x00, 0x02,
		0x05, 0x42,
	})
	c.Assert(ok, Equals, true)
	c.Assert(m.instanceTag, Equals, uint32(0x4253112E))
	c.Assert(m.identity, DeepEquals, "foobar@blarg.com/foo")
	c.Assert(m.versions, DeepEquals, []byte{0x05, 0x42})
}
