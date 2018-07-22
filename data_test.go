package prekeyserver

import (
	"time"

	. "gopkg.in/check.v1"
)

func (s *GenericServerSuite) Test_appendLong_serializesTimeCorrectly(c *C) {
	tt := time.Date(2028, 11, 5, 13, 46, 00, 13, time.UTC)
	num := tt.Unix()
	c.Assert(num, Equals, int64(0x6EB04118))
	c.Assert(appendLong(nil, uint64(num)), DeepEquals, []byte{0x00, 0x00, 0x00, 0x00, 0x6e, 0xb0, 0x41, 0x18})

	tt2 := time.Date(1968, 11, 5, 13, 46, 00, 13, time.UTC)
	num2 := tt2.Unix()
	c.Assert(num2, Equals, int64(-0x022B9768))
	c.Assert(appendLong(nil, uint64(num2)), DeepEquals, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFD, 0xD4, 0x68, 0x98})
}

func (s *GenericServerSuite) Test_extractLong_deserializesTimeCorrectly(c *C) {
	expected := time.Date(2028, 11, 5, 13, 46, 00, 00, time.UTC)
	_, res, _ := extractLong([]byte{0x00, 0x00, 0x00, 0x00, 0x6e, 0xb0, 0x41, 0x18})

	c.Assert(res, Equals, uint64(0x6EB04118))
	c.Assert(int64(res), Equals, int64(0x6EB04118))
	t := time.Unix(int64(res), 0).In(time.UTC)
	c.Assert(t, Equals, expected)

	expected2 := time.Date(1968, 11, 5, 13, 46, 00, 00, time.UTC)
	_, res2, _ := extractLong([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFD, 0xD4, 0x68, 0x98})

	c.Assert(res2, Equals, uint64(0xfffffffffdd46898))
	c.Assert(int64(res2), Equals, int64(-0x022B9768))
	tt := time.Unix(int64(res2), 0).In(time.UTC)
	c.Assert(tt, Equals, expected2)
}
