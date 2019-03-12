package gotrax

import . "gopkg.in/check.v1"

func (s *GotraxSuite) Test_KdfPrekeyServer_generatesCorrectValues(c *C) {
	v := KdfPrekeyServer(usageBraceKey, 3, []byte("one"), []byte("two"))
	c.Assert(v, DeepEquals, []byte{
		0xce, 0x5b, 0x44,
	})

	v2 := KdfPrekeyServer(usageFingerprint, 3, []byte("one"), []byte("two"))
	c.Assert(v2, DeepEquals, []byte{
		0xc8, 0x05, 0x30,
	})
}

func (s *GotraxSuite) Test_KdfxPrekeyServer_generatesCorrectValues(c *C) {
	v := make([]byte, 3)
	KdfxPrekeyServer(usageBraceKey, v, []byte("one"), []byte("two"))
	c.Assert(v, DeepEquals, []byte{
		0xce, 0x5b, 0x44,
	})

	KdfxPrekeyServer(usageFingerprint, v, []byte("one"), []byte("two"))
	c.Assert(v, DeepEquals, []byte{
		0xc8, 0x05, 0x30,
	})
}

func (s *GotraxSuite) Test_Kdf_generatesCorrectValues(c *C) {
	v := Kdf(usageBraceKey, 3, []byte("one"), []byte("two"))
	c.Assert(v, DeepEquals, []byte{
		0x7e, 0xa6, 0x9e,
	})

	v2 := Kdf(usageFingerprint, 3, []byte("one"), []byte("two"))
	c.Assert(v2, DeepEquals, []byte{
		0x89, 0x6b, 0x14,
	})
}

func (s *GotraxSuite) Test_Kdfx_generatesCorrectValues(c *C) {
	v := make([]byte, 3)
	Kdfx(usageBraceKey, v, []byte("one"), []byte("two"))
	c.Assert(v, DeepEquals, []byte{
		0x7e, 0xa6, 0x9e,
	})

	Kdfx(usageFingerprint, v, []byte("one"), []byte("two"))
	c.Assert(v, DeepEquals, []byte{
		0x89, 0x6b, 0x14,
	})
}
