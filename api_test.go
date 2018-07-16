package prekeyserver

import (
	"bytes"
	"crypto/rand"
	"errors"
	"time"

	. "gopkg.in/check.v1"
)

func (s *GenericServerSuite) Test_realFactory_randReader_returnsTheDefaultRandReader(c *C) {
	r := &realFactory{}
	c.Assert(r.randReader(), Equals, rand.Reader)
}

func (s *GenericServerSuite) Test_realFactory_randReader_returnsTheGivenReader(c *C) {
	f := fixtureRand()
	r := &realFactory{r: f}
	c.Assert(r.randReader(), Equals, f)
}

func (s *GenericServerSuite) Test_CreateFactory_returnsARealFactoryWithTheGivenRandomness(c *C) {
	f := fixtureRand()
	fact := CreateFactory(f)
	rf, ok := fact.(*realFactory)
	c.Assert(ok, Equals, true)
	c.Assert(rf.r, Equals, f)
}

func (s *GenericServerSuite) Test_inMemoryStorageFactory_createStorage_returnsAnInMemoryStorageFactory(c *C) {
	res := (&inMemoryStorageFactory{}).createStorage()
	c.Assert(res, Not(IsNil))
	c.Assert(res, FitsTypeOf, &inMemoryStorage{})
}

func (s *GenericServerSuite) Test_realFactory_LoadStorageType_returnsInMemoryStorage(c *C) {
	res, _ := (&realFactory{}).LoadStorageType("in-memory")
	c.Assert(res, Not(IsNil))
	c.Assert(res, FitsTypeOf, &inMemoryStorageFactory{})
}

func (s *GenericServerSuite) Test_realFactory_LoadStorageType_givesErrorForUnknownStorageType(c *C) {
	res, e := (&realFactory{}).LoadStorageType("unknown-storage-please-don't-create")
	c.Assert(res, IsNil)
	c.Assert(e, ErrorMatches, "unknown storage type")
}

func (s *GenericServerSuite) Test_realFactory_CreateKeypair_createsAKeypairFromTheGivenRandomness(c *C) {
	r := fixtureRand()
	res := (&realFactory{r: r}).CreateKeypair()
	c.Assert(res, Not(IsNil))
	c.Assert(res, FitsTypeOf, &keypair{})
	c.Assert(res.(*keypair).sym[:], DeepEquals, []byte{
		0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
		0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
		0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
		0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
		0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
		0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
		0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
		0xab})
}

func (s *GenericServerSuite) Test_realFactory_NewServer_createsAServerWithTheGivenValues(c *C) {
	f := &realFactory{r: fixtureRand()}
	kp := f.CreateKeypair()
	res := f.NewServer("foobar", kp, 42, &inMemoryStorageFactory{}, time.Duration(25), time.Duration(77))
	c.Assert(res, Not(IsNil))
	c.Assert(res, FitsTypeOf, &GenericServer{})
	gs := res.(*GenericServer)
	c.Assert(gs.identity, Equals, "foobar")
	c.Assert(gs.fingerprint, DeepEquals, fingerprint(kp.realKeys().fingerprint()))
	c.Assert(gs.key, Equals, kp)
	c.Assert(gs.fragLen, Equals, 42)
	c.Assert(gs.fragmentations, Not(IsNil))
	c.Assert(gs.sessions, Not(IsNil))
	c.Assert(gs.storageImpl, Not(IsNil))
	c.Assert(gs.sessionTimeout, Equals, time.Duration(25))
	c.Assert(gs.fragmentationTimeout, Equals, time.Duration(77))
	c.Assert(gs.messageHandler, Not(IsNil))
	c.Assert(gs.messageHandler.(*otrngMessageHandler).s, Equals, gs)
}

func (s *GenericServerSuite) Test_keypairInStorage_intoKeypair_decodesACorrectMessage(c *C) {
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

	expectedKp := deriveKeypair(sym)

	kis := &keypairInStorage{
		Symmetric: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Private:   "S0Cr1lAIHXdTixCTeWQAQRJksS0o9Ftr/EcO0yemXi9fJOTAWj+c9h9QVW5M0KDm9uH04SopxiA=",
		Public:    "BXLBTLEwd0S5Lzg3+ZY5q7sg/8Rx2J2dVFNJ3HAOASdJHwYTFPr4moXHB2C9AYilZp0aQ5Pwg0uA",
	}

	kp, e := kis.intoKeypair()
	c.Assert(e, IsNil)
	c.Assert(kp.sym, DeepEquals, expectedKp.sym)
	c.Assert(kp.pub.k.Equals(expectedKp.pub.k), Equals, true)
	c.Assert(kp.priv.k.Equals(expectedKp.priv.k), Equals, true)
}

func (s *GenericServerSuite) Test_keypairInStorage_intoKeypair_generatesAnErrorForBadBase64OnSymmetric(c *C) {
	kis := &keypairInStorage{
		Symmetric: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Private:   "S0Cr1lAIHXdTixCTeWQAQRJksS0o9Ftr/EcO0yemXi9fJOTAWj+c9h9QVW5M0KDm9uH04SopxiA=",
		Public:    "BXLBTLEwd0S5Lzg3+ZY5q7sg/8Rx2J2dVFNJ3HAOASdJHwYTFPr4moXHB2C9AYilZp0aQ5Pwg0uA",
	}

	_, e := kis.intoKeypair()
	c.Assert(e, ErrorMatches, "couldn't decode symmetric key")
}

func (s *GenericServerSuite) Test_keypairInStorage_intoKeypair_generatesAnErrorForBadBase64OnPrivate(c *C) {
	kis := &keypairInStorage{
		Symmetric: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Private:   "S0Cr1lAIHXdTixCTeWQAQRJksS0o9Ftr/EcO0yemXi9fJOTAWj+c9h9QVW5M0KDm9uH04SopxiA",
		Public:    "BXLBTLEwd0S5Lzg3+ZY5q7sg/8Rx2J2dVFNJ3HAOASdJHwYTFPr4moXHB2C9AYilZp0aQ5Pwg0uA",
	}

	_, e := kis.intoKeypair()
	c.Assert(e, ErrorMatches, "couldn't decode private key")
}

func (s *GenericServerSuite) Test_keypairInStorage_intoKeypair_generatesAnErrorForBadBase64OnPublic(c *C) {
	kis := &keypairInStorage{
		Symmetric: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Private:   "S0Cr1lAIHXdTixCTeWQAQRJksS0o9Ftr/EcO0yemXi9fJOTAWj+c9h9QVW5M0KDm9uH04SopxiA=",
		Public:    "BXLBTLEwd0S5Lzg3+ZY5q7sg/8Rx2J2dVFNJ3HAOASdJHwYTFPr4moXHB2C9AYilZp0aQ5Pwg0u",
	}

	_, e := kis.intoKeypair()
	c.Assert(e, ErrorMatches, "couldn't decode public key")
}

func (s *GenericServerSuite) Test_keypairInStorage_intoKeypair_generatesAnErrorForBadPrivateScalar(c *C) {
	kis := &keypairInStorage{
		Symmetric: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Private:   "S0Cr1lAIHXdTixCTeWQAQRJksS0o9Ftr/EcO0yemXi9fJOTAWj+c9h9QVW5M0KDm9uH04Sop",
		Public:    "BXLBTLEwd0S5Lzg3+ZY5q7sg/8Rx2J2dVFNJ3HAOASdJHwYTFPr4moXHB2C9AYilZp0aQ5Pwg0uA",
	}

	_, e := kis.intoKeypair()
	c.Assert(e, ErrorMatches, "couldn't decode scalar for private key")
}

func (s *GenericServerSuite) Test_keypairInStorage_intoKeypair_generatesAnErrorForBadPublicPoint(c *C) {
	kis := &keypairInStorage{
		Symmetric: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Private:   "S0Cr1lAIHXdTixCTeWQAQRJksS0o9Ftr/EcO0yemXi9fJOTAWj+c9h9QVW5M0KDm9uH04SopxiA=",
		Public:    "BXLBTLEwd0S5Lzg3+ZY5q7sg/8Rx2J2dVFNJ3HAOASdJHwYTFPr4moXHB2C9AYilZp0aQ5Pw",
	}

	_, e := kis.intoKeypair()
	c.Assert(e, ErrorMatches, "couldn't decode point for public key")
}

func (s *GenericServerSuite) Test_realFactory_LoadKeypairFrom_canLoadAKeypairCorrectly(c *C) {
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

	expectedKp := deriveKeypair(sym)

	b := bytes.NewBufferString("{\"Symmetric\":\"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"," +
		"\"Private\":\"S0Cr1lAIHXdTixCTeWQAQRJksS0o9Ftr/EcO0yemXi9fJOTAWj+c9h9QVW5M0KDm9uH04SopxiA=\"," +
		"\"Public\":\"BXLBTLEwd0S5Lzg3+ZY5q7sg/8Rx2J2dVFNJ3HAOASdJHwYTFPr4moXHB2C9AYilZp0aQ5Pwg0uA\"}\n")
	f := &realFactory{}
	kp, e := f.LoadKeypairFrom(b)
	c.Assert(e, IsNil)
	c.Assert(kp.realKeys().sym, DeepEquals, expectedKp.sym)
	c.Assert(kp.realKeys().pub.k.Equals(expectedKp.pub.k), Equals, true)
	c.Assert(kp.realKeys().priv.k.Equals(expectedKp.priv.k), Equals, true)
}

type erroringReader struct{}

func (*erroringReader) Read([]byte) (int, error) {
	return 0, errors.New("something bad")
}

func (s *GenericServerSuite) Test_realFactory_LoadKeypairFrom_willReturnAnErrorFromReading(c *C) {
	f := &realFactory{}
	kp, e := f.LoadKeypairFrom(&erroringReader{})
	c.Assert(kp, IsNil)
	c.Assert(e, ErrorMatches, "something bad")
}

func (s *GenericServerSuite) Test_realFactory_LoadKeypairFrom_willReturnAnErrorFromParsing(c *C) {
	b := bytes.NewBufferString("{\"Symmetric\":\"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"," +
		"\"Private\":\"S0Cr1lAIHXdTixCTeWQAQRJksS0o9Ftr/EcO0yemXi9fJOTAWj+c9h9QVW5M0KDm9uH04SopxiA\"," +
		"\"Public\":\"BXLBTLEwd0S5Lzg3+ZY5q7sg/8Rx2J2dVFNJ3HAOASdJHwYTFPr4moXHB2C9AYilZp0aQ5Pwg0uA\"}\n")
	f := &realFactory{}
	kp, e := f.LoadKeypairFrom(b)
	c.Assert(kp, IsNil)
	c.Assert(e, ErrorMatches, "couldn't decode private key")
}

func (s *GenericServerSuite) Test_realFactory_StoreKeysInto_willPrintTheExpectedJson(c *C) {
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
	rf := &realFactory{}

	kp := deriveKeypair(sym)
	var b bytes.Buffer
	rf.StoreKeysInto(kp, &b)

	c.Assert(b.String(), Equals,
		"{\"Symmetric\":\"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\","+
			"\"Private\":\"S0Cr1lAIHXdTixCTeWQAQRJksS0o9Ftr/EcO0yemXi9fJOTAWj+c9h9QVW5M0KDm9uH04SopxiA=\","+
			"\"Public\":\"BXLBTLEwd0S5Lzg3+ZY5q7sg/8Rx2J2dVFNJ3HAOASdJHwYTFPr4moXHB2C9AYilZp0aQ5Pwg0uA\"}\n")
}

type erroringWriter struct{}

func (*erroringWriter) Write([]byte) (int, error) {
	return 0, errors.New("something bad")
}

func (s *GenericServerSuite) Test_realFactory_StoreKeysInto_willReturnAnyErrorEncountered(c *C) {
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
	rf := &realFactory{}

	kp := deriveKeypair(sym)
	e := rf.StoreKeysInto(kp, &erroringWriter{})

	c.Assert(e, ErrorMatches, "something bad")
}
