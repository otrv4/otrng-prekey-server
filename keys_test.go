package prekeyserver

import (
	. "gopkg.in/check.v1"
)

func (s *GenericServerSuite) Test_deriveEDDSAKeypair_derivesTheCorrectData(c *C) {
	sym1 := [57]byte{
		0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,
	}
	expectedPrivateKey := []byte{
		0XDD, 0X86, 0X6D, 0X00, 0X25, 0XDE, 0XF2, 0XE5,
		0X3C, 0XB0, 0X2C, 0X62, 0XF7, 0X8E, 0X6F, 0X75,
		0X2F, 0X90, 0XA6, 0X26, 0X1D, 0X3F, 0X7B, 0X53,
		0X5E, 0X79, 0X65, 0X7A, 0XBA, 0X8B, 0X43, 0XE8,
		0XEA, 0XFF, 0XF6, 0X70, 0XF4, 0XF6, 0X85, 0X8A,
		0X22, 0X58, 0XD7, 0X06, 0X26, 0XB4, 0X3F, 0X69,
		0X81, 0X8E, 0XC5, 0X72, 0X7E, 0XEF, 0XFB, 0X37,
	}
	expectedPublicKey := []byte{
		0X61, 0XFA, 0X1F, 0X15, 0X35, 0X82, 0XF5, 0XF6,
		0X42, 0XF2, 0X72, 0X02, 0XE9, 0XC2, 0X57, 0X06,
		0X1A, 0X7C, 0XB8, 0XC4, 0X79, 0X91, 0X74, 0XB3,
		0XA9, 0XBD, 0X87, 0XA4, 0XF3, 0XB1, 0X87, 0X0F,
		0X8C, 0XEE, 0X9C, 0X09, 0XDC, 0X8E, 0X8B, 0X74,
		0X31, 0X0E, 0X80, 0X55, 0X73, 0X9D, 0X63, 0X43,
		0X30, 0XDB, 0XB9, 0X72, 0X6D, 0X48, 0X4E, 0X27,
		0X80,
	}

	kp := deriveEDDSAKeypair(sym1)

	c.Assert(kp.sym[:], DeepEquals, sym1[:])
	c.Assert(kp.priv.k.Encode(), DeepEquals, expectedPrivateKey)
	c.Assert(kp.pub.k.DSAEncode(), DeepEquals, expectedPublicKey)
}

func (s *GenericServerSuite) Test_deriveECDHKeypair_derivesTheCorrectData(c *C) {
	// This test is based on the libotr-ng implementation
	// It is NOT correct, according to the spec at this point.
	sym1 := [57]byte{
		0x2B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,
	}
	expectedSym := []byte{
		0XDE, 0X2E, 0X60, 0X90, 0X8A, 0X76, 0X47, 0X24,
		0X8F, 0XB1, 0X66, 0XEB, 0XC5, 0XD9, 0XF6, 0X3F,
		0XEB, 0XB9, 0X60, 0X3C, 0XFF, 0XCB, 0X6A, 0X05,
		0XAA, 0X40, 0X84, 0X3E, 0XB9, 0X9B, 0XB4, 0X74,
		0X6D, 0X2E, 0XE7, 0XE0, 0X49, 0XBE, 0X31, 0X47,
		0XA5, 0X1B, 0X38, 0X3C, 0X28, 0X64, 0X1D, 0X45,
		0X12, 0X39, 0X41, 0X27, 0X97, 0X33, 0XF9, 0XD7,
		0X7C,
	}
	expectedPrivateKey := []byte{
		0XCD, 0X08, 0X3F, 0XB4, 0X6E, 0X92, 0X17, 0XC3,
		0X5D, 0XF8, 0XBE, 0XD2, 0X68, 0X2D, 0X40, 0XB7,
		0X60, 0X59, 0XD0, 0XE6, 0XE6, 0XE8, 0X05, 0XB1,
		0X4F, 0XD2, 0X11, 0X13, 0X53, 0X0F, 0X03, 0XEB,
		0X24, 0XE0, 0X42, 0X97, 0XF8, 0XEC, 0XA9, 0X31,
		0X49, 0X64, 0X7E, 0XCA, 0XF6, 0XA7, 0XE3, 0X0B,
		0X03, 0X30, 0XB9, 0XD2, 0X78, 0X09, 0X46, 0X31,
	}
	expectedPublicKey := []byte{
		0X20, 0XC4, 0X2C, 0XDC, 0XDA, 0X0F, 0XB0, 0X18,
		0X17, 0XEA, 0X5D, 0XEF, 0X5A, 0XC7, 0XDC, 0X22,
		0X2A, 0X47, 0X59, 0X58, 0XDD, 0X3F, 0XDC, 0XBA,
		0X22, 0X2E, 0X36, 0X78, 0X95, 0XC0, 0X17, 0XC4,
		0X7B, 0XA4, 0XEF, 0X1E, 0XD2, 0XB9, 0X5D, 0X0B,
		0X54, 0XDF, 0XB1, 0XDD, 0X0E, 0X7B, 0X07, 0X53,
		0X89, 0XE9, 0X01, 0X4D, 0XA8, 0X78, 0X54, 0XD4,
		0X80,
	}

	kp := deriveECDHKeypair(sym1)

	c.Assert(kp.sym[:], DeepEquals, expectedSym)
	c.Assert(kp.priv.k.Encode(), DeepEquals, expectedPrivateKey)
	c.Assert(kp.pub.k.DSAEncode(), DeepEquals, expectedPublicKey)
}

func (s *GenericServerSuite) Test_fingerprint_returnsCorrectFingerprint(c *C) {
	sym := [57]byte{
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,
	}

	expectedFpr := fingerprint{
		0X7B, 0XDC, 0XB0, 0X56, 0X44, 0XEB, 0X07, 0XD1, 0XA8, 0XCD, 0X4D, 0XCB,
		0X82, 0XA6, 0X0B, 0XFF, 0X3F, 0X29, 0X3C, 0X83, 0X3A, 0XD6, 0XBC, 0XC9,
		0XC9, 0X97, 0XCC, 0X92, 0X82, 0XD5, 0X0E, 0X49, 0XC6, 0X89, 0XD1, 0XDB,
		0X4D, 0X42, 0XD7, 0X26, 0X37, 0X49, 0X91, 0XCE, 0X68, 0XE0, 0X54, 0X57,
		0X81, 0XBF, 0XE4, 0X7D, 0X46, 0X73, 0X9F, 0X40,
	}

	kp := deriveEDDSAKeypair(sym)
	fpr := kp.fingerprint()
	c.Assert(fpr, DeepEquals, expectedFpr)
}
