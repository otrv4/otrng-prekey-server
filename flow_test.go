package prekeyserver

import (
	"errors"
	"time"

	"github.com/otrv4/ed448"
	. "gopkg.in/check.v1"
)

func generateSitaClientProfile(longTerm *keypair) *clientProfile {
	sita := &clientProfile{}
	sita.identifier = 0xAABBCCDD
	sita.instanceTag = 0x1245ABCD
	sita.publicKey = longTerm.pub
	sita.versions = []byte{0x04}
	sita.expiration = time.Date(2028, 11, 5, 13, 46, 00, 13, time.UTC)
	sita.dsaKey = nil
	sita.transitionalSignature = nil
	sita.sig = &eddsaSignature{s: [114]byte{
		0x4b, 0x7f, 0xd8, 0xeb, 0x3b, 0xf3, 0x91, 0xca,
		0x5, 0x82, 0x4b, 0x81, 0x67, 0x6, 0x17, 0x6b,
		0x49, 0xdf, 0xe, 0x3, 0x32, 0xfa, 0x19, 0x4,
		0x8b, 0xe6, 0xd3, 0x84, 0x9b, 0xc8, 0x5d, 0xba,
		0x60, 0x7e, 0xb8, 0xfe, 0xcb, 0x85, 0x37, 0x90,
		0xfa, 0x2f, 0x52, 0x31, 0x1b, 0x62, 0x50, 0x5b,
		0xf4, 0xf0, 0x97, 0x75, 0x32, 0x73, 0x4f, 0xbe,
		0x0, 0x65, 0xc7, 0xc0, 0x30, 0x36, 0xbf, 0x27,
		0x90, 0xe5, 0x77, 0x5b, 0x3, 0xce, 0xcc, 0x42,
		0xbe, 0x6, 0x87, 0x4b, 0xf3, 0x9e, 0x98, 0x32,
		0x9c, 0xe6, 0xd7, 0x76, 0x6, 0x9e, 0x32, 0x20,
		0x30, 0x28, 0xbd, 0x51, 0xfc, 0x35, 0xa6, 0x19,
		0xa6, 0x16, 0x76, 0xc1, 0x4e, 0x47, 0xaa, 0x59,
		0xd3, 0xee, 0x1e, 0x31, 0x3f, 0x40, 0xd3, 0x5a,
		0x2a, 0x0,
	}}
	return sita
}

func generateSitaIPoint() *keypair {
	return deriveECDHKeypair([symKeyLength]byte{0x42, 0x11, 0xCC, 0x22, 0xDD, 0x11, 0xFF})
}

type testData struct {
	instanceTag   uint32
	longTerm      *keypair
	clientProfile *clientProfile
	i             *keypair
}

func generateSitaTestData() *testData {
	t := &testData{}
	t.instanceTag = 0x1245ABCD
	t.longTerm = deriveEDDSAKeypair([symKeyLength]byte{0x42, 0x00, 0x00, 0x55, 0x55, 0x00, 0x00, 0x55})
	t.clientProfile = generateSitaClientProfile(t.longTerm)
	t.i = generateSitaIPoint()
	return t
}

var sita = generateSitaTestData()

func (s *GenericServerSuite) Test_flow_CheckStorageNumber(c *C) {
	stor := createInMemoryStorage()
	serverKey := deriveEDDSAKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        fixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.pub.fingerprint(),
		storageImpl: stor,
	}
	mh := &otrngMessageHandler{s: gs}
	gs.messageHandler = mh

	d1 := generateDake1(sita.instanceTag, sita.clientProfile, sita.i.pub.k)

	r, e := mh.handleMessage("sita@example.org", d1.serialize())

	c.Assert(e, IsNil)

	d2 := dake2Message{}
	_, ok := d2.deserialize(r)

	c.Assert(ok, Equals, true)
	c.Assert(d2.instanceTag, Equals, uint32(0x1245ABCD))
	c.Assert(d2.serverIdentity, DeepEquals, []byte("masterOfKeys.example.org"))
	c.Assert(d2.serverFingerprint[:], DeepEquals, []byte{
		0x32, 0x7c, 0xd2, 0xfc, 0xcb, 0x3b, 0xd1, 0x1d,
		0x63, 0x6a, 0x33, 0x44, 0xd5, 0x4b, 0xc9, 0xd,
		0x8d, 0x7e, 0xf3, 0x38, 0x39, 0x1e, 0x9d, 0x21,
		0x1f, 0x66, 0x39, 0x61, 0xd0, 0xf7, 0xea, 0x4,
		0xf0, 0x12, 0xd0, 0x76, 0xe3, 0x5a, 0x9c, 0x7a,
		0xe7, 0x37, 0xfd, 0xd8, 0xab, 0x1e, 0x3e, 0xf1,
		0xbd, 0x66, 0x57, 0xa2, 0x71, 0x1, 0xf7, 0x4e,
	})
	c.Assert(d2.s.DSAEncode(), DeepEquals, []byte{
		0xd9, 0xe9, 0xed, 0x15, 0xf1, 0x57, 0x6f, 0x39,
		0x80, 0xa4, 0x57, 0xa0, 0x3c, 0xc5, 0x9, 0xec,
		0xa0, 0x13, 0x90, 0x57, 0xfc, 0xb, 0x33, 0x36,
		0x55, 0x17, 0xf, 0x7f, 0x34, 0x8e, 0xe1, 0x15,
		0x19, 0xdc, 0x86, 0x2f, 0x82, 0xb, 0x3a, 0xe,
		0x42, 0x9, 0xc3, 0xdb, 0xd0, 0x5b, 0x93, 0x19,
		0x2c, 0x39, 0x96, 0x2a, 0x51, 0xfe, 0x58, 0xf9,
		0x0})

	c.Assert(d2.sigma.c1.Encode(), DeepEquals, []byte{
		0x3e, 0x4f, 0x9a, 0xe1, 0x98, 0x28, 0x67, 0x86,
		0xf1, 0xba, 0x33, 0x60, 0x31, 0x54, 0x50, 0x49,
		0x5, 0xfa, 0xc0, 0x93, 0xf5, 0x5d, 0x64, 0xca,
		0x22, 0x8d, 0x27, 0x22, 0x6c, 0xf6, 0x59, 0xd9,
		0xb3, 0x31, 0x31, 0x73, 0x10, 0xb4, 0x6e, 0xc6,
		0x17, 0xba, 0x5f, 0x91, 0xdd, 0x31, 0xb5, 0x9,
		0x83, 0x1, 0x51, 0x7c, 0x8, 0x2e, 0x1c, 0x33})

	c.Assert(d2.sigma.r1.Encode(), DeepEquals, []byte{
		0x47, 0x71, 0x5b, 0x81, 0xa8, 0x56, 0x47, 0x16,
		0x5, 0x8f, 0x9a, 0x2e, 0x9b, 0x2c, 0x55, 0xc3,
		0xd7, 0x0, 0xd3, 0x26, 0x13, 0xf5, 0x93, 0xe4,
		0xf4, 0xcb, 0x98, 0xb7, 0xe7, 0x81, 0xd, 0x35,
		0xa7, 0xa5, 0x59, 0x74, 0x9b, 0x7d, 0x19, 0x63,
		0x20, 0x5c, 0x1, 0x3b, 0x79, 0x70, 0x35, 0x33,
		0xfa, 0x1f, 0x38, 0xe3, 0x81, 0x96, 0x78, 0x2e})

	c.Assert(d2.sigma.c2.Encode(), DeepEquals, []byte{
		0x8d, 0x45, 0xb5, 0xdd, 0xb6, 0x5d, 0x35, 0xbb,
		0xc, 0x42, 0xd0, 0x3b, 0xbe, 0x7b, 0x81, 0xd3,
		0x6f, 0xdc, 0x85, 0xe1, 0xed, 0x61, 0x2a, 0xec,
		0xd4, 0xec, 0xd3, 0xd5, 0x24, 0xd7, 0x9e, 0xb0,
		0x16, 0xff, 0x0, 0x21, 0xc2, 0xf6, 0x81, 0xac,
		0xf9, 0xb7, 0x46, 0x2f, 0x2f, 0x39, 0x1, 0xd3,
		0x74, 0x28, 0x23, 0xd, 0xc5, 0x1b, 0xb3, 0x16})

	c.Assert(d2.sigma.r2.Encode(), DeepEquals, []byte{
		0xf9, 0xbd, 0xb1, 0x44, 0x23, 0xf4, 0xe4, 0xf6,
		0x7a, 0x7e, 0x27, 0x6d, 0x1e, 0x48, 0x95, 0x98,
		0x9e, 0x4a, 0x3a, 0x42, 0x47, 0x2a, 0xc7, 0x78,
		0x2b, 0x33, 0x5a, 0x44, 0x9e, 0xbf, 0xb1, 0x8d,
		0xda, 0xb5, 0x89, 0xc4, 0x4, 0xf4, 0x8f, 0xab,
		0x5c, 0xd1, 0x94, 0xe4, 0xc8, 0x59, 0x22, 0x57,
		0x51, 0xe5, 0xae, 0xb0, 0x59, 0xcf, 0x49, 0x22})

	c.Assert(d2.sigma.c3.Encode(), DeepEquals, []byte{
		0x31, 0xb3, 0xc2, 0xa1, 0x10, 0x46, 0x2d, 0xd2,
		0x4a, 0x3c, 0x4d, 0x8c, 0x2c, 0xba, 0xd4, 0xe3,
		0x6e, 0x73, 0xfb, 0x8, 0x1f, 0x92, 0xb4, 0x88,
		0x85, 0x50, 0xd, 0xe4, 0x26, 0x9a, 0x3b, 0x86,
		0x94, 0x5a, 0xf3, 0x33, 0xb3, 0x95, 0x10, 0x6f,
		0x54, 0x6c, 0x14, 0xde, 0x51, 0x97, 0x14, 0x86,
		0x1f, 0xb0, 0x27, 0xdf, 0x57, 0x48, 0x7c, 0x3f})

	c.Assert(d2.sigma.r3.Encode(), DeepEquals, []byte{
		0x75, 0x8f, 0x53, 0x1c, 0x7b, 0x2f, 0x4, 0xbf,
		0x34, 0x16, 0xf0, 0x8e, 0x7, 0x19, 0x53, 0x9f,
		0x9c, 0xab, 0xcd, 0xab, 0xfa, 0x5f, 0x3a, 0xe3,
		0x55, 0xf5, 0x85, 0xbd, 0x3e, 0x46, 0x8b, 0xe,
		0xfb, 0x1a, 0xc, 0x1f, 0xa, 0xe3, 0x9e, 0x1e,
		0x93, 0x4a, 0x86, 0x95, 0x4c, 0x7, 0x0, 0xda,
		0xee, 0xd2, 0x8c, 0x4, 0xc0, 0x57, 0x71, 0x28})

	phi := appendData(appendData(nil, []byte("sita@example.org")), []byte(gs.identity))

	t := append([]byte{}, 0x01)
	t = append(t, kdfx(usageReceiverClientProfile, 64, sita.clientProfile.serialize())...)
	t = append(t, kdfx(usageReceiverPrekeyCompositeIdentity, 64, gs.compositeIdentity())...)
	t = append(t, serializePoint(sita.i.pub.k)...)
	t = append(t, serializePoint(d2.s)...)
	t = append(t, kdfx(usageReceiverPrekeyCompositePHI, 64, phi)...)

	sigma, _ := generateSignature(gs, sita.longTerm.priv, sita.longTerm.pub, sita.longTerm.pub, gs.key.pub, &publicKey{d2.s}, t)

	sk := kdfx(usageSK, skLength, serializePoint(ed448.PointScalarMul(d2.s, sita.i.priv.k)))
	sitaPrekeyMac := kdfx(usagePreMACKey, 64, sk)
	msg := generateStorageInformationRequestMessage(sitaPrekeyMac)

	d3 := generateDake3(sita.instanceTag, sigma, msg.serialize())

	r, e = mh.handleMessage("sita@example.org", d3.serialize())

	c.Assert(e, IsNil)

	res := &storageStatusMessage{}
	_, ok = res.deserialize(r)
	c.Assert(ok, Equals, true)
	c.Assert(res, Not(IsNil))
	c.Assert(res.instanceTag, Equals, uint32(0x1245ABCD))
	c.Assert(res.number, Equals, uint32(0x00))
	c.Assert(res.mac[:], DeepEquals, []byte{
		0x2d, 0x1, 0xff, 0xd4, 0x39, 0xb6, 0xbb, 0x9f,
		0xcd, 0x36, 0x69, 0xe8, 0xae, 0x9a, 0x43, 0x36,
		0xf2, 0x37, 0x2f, 0x44, 0x75, 0x1f, 0xeb, 0x6b,
		0x71, 0x2, 0xba, 0xc4, 0xf6, 0xf, 0x45, 0xcf,
		0xbe, 0x69, 0x1f, 0xc8, 0xd3, 0x4c, 0x7c, 0xca,
		0x1a, 0xe, 0x50, 0x76, 0x95, 0xa4, 0x9c, 0xc3,
		0x1e, 0x4, 0x5, 0x85, 0x11, 0xf8, 0x2f, 0x3c,
		0x8b, 0xdf, 0x28, 0xdc, 0x21, 0xe9, 0xc8, 0x2e,
	})
}

func (s *GenericServerSuite) Test_flow_retrieveEnsemblesFromUnknownPerson(c *C) {
	stor := createInMemoryStorage()
	retM := &ensembleRetrievalQueryMessage{
		instanceTag: 0x12445511,
		identity:    "sita@example.org",
		versions:    []byte{0x04},
	}

	serverKey := deriveEDDSAKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        fixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.pub.fingerprint(),
		storageImpl: stor,
	}
	mh := &otrngMessageHandler{s: gs}

	r, e := mh.handleMessage("rama@example.org", retM.serialize())
	c.Assert(e, IsNil)

	rm := &noPrekeyEnsemblesMessage{}
	_, ok := rm.deserialize(r)

	c.Assert(ok, Equals, true)
	c.Assert(rm.instanceTag, Equals, uint32(0x12445511))
	c.Assert(rm.message, Equals, "No Prekey Messages available for this identity")
}

func (s *GenericServerSuite) Test_flow_invalidUserProfileInDAKE1(c *C) {
	serverKey := deriveEDDSAKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        fixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.pub.fingerprint(),
	}
	mh := &otrngMessageHandler{s: gs}

	badcp := generateSitaClientProfile(sita.longTerm)
	badcp.instanceTag = 0x42424242

	d1 := generateDake1(sita.instanceTag, badcp, sita.i.pub.k)

	_, e := mh.handleMessage("sita@example.org", d1.serialize())

	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid client profile"))
}

func (s *GenericServerSuite) Test_flow_invalidPointI(c *C) {
	serverKey := deriveEDDSAKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        fixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.pub.fingerprint(),
	}
	mh := &otrngMessageHandler{s: gs}

	badcp := generateSitaClientProfile(sita.longTerm)
	badi := ed448.NewPoint([16]uint32{0x00}, [16]uint32{0x01}, [16]uint32{0x01}, [16]uint32{0x00})
	d1 := generateDake1(sita.instanceTag, badcp, badi)

	_, e := mh.handleMessage("sita@example.org", d1.serialize())

	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid point I"))
}

func (s *GenericServerSuite) Test_flow_invalidDAKE3(c *C) {
	serverKey := deriveEDDSAKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        fixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.pub.fingerprint(),
	}
	mh := &otrngMessageHandler{s: gs}

	d1 := generateDake1(sita.instanceTag, sita.clientProfile, sita.i.pub.k)

	r, e := mh.handleMessage("sita@example.org", d1.serialize())

	c.Assert(e, IsNil)

	d2 := dake2Message{}
	_, ok := d2.deserialize(r)

	c.Assert(ok, Equals, true)

	phi := appendData(appendData(nil, []byte("sita@example.org")), []byte(gs.identity))

	t := append([]byte{}, 0x01)
	t = append(t, kdfx(usageReceiverClientProfile, 64, sita.clientProfile.serialize())...)
	t = append(t, kdfx(usageReceiverPrekeyCompositeIdentity, 64, gs.compositeIdentity())...)
	t = append(t, serializePoint(sita.i.pub.k)...)
	t = append(t, serializePoint(d2.s)...)
	t = append(t, kdfx(usageReceiverPrekeyCompositePHI, 64, phi)...)

	sigma, _ := generateSignature(gs, sita.longTerm.priv, sita.longTerm.pub, sita.longTerm.pub, gs.key.pub, &publicKey{d2.s}, t)

	sk := kdfx(usageSK, skLength, serializePoint(ed448.PointScalarMul(d2.s, sita.i.priv.k)))
	sitaPrekeyMac := kdfx(usagePreMACKey, 64, sk)
	msg := generateStorageInformationRequestMessage(sitaPrekeyMac)

	d3 := generateDake3(0xBADBADBA, sigma, msg.serialize())
	r, e = mh.handleMessage("sita@example.org", d3.serialize())

	c.Assert(e, Not(IsNil))
}

func (s *GenericServerSuite) Test_flow_invalidMACused(c *C) {
	serverKey := deriveEDDSAKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        fixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.pub.fingerprint(),
	}
	mh := &otrngMessageHandler{s: gs}
	gs.messageHandler = mh

	d1 := generateDake1(sita.instanceTag, sita.clientProfile, sita.i.pub.k)

	r, e := mh.handleMessage("sita@example.org", d1.serialize())

	c.Assert(e, IsNil)

	d2 := dake2Message{}
	_, ok := d2.deserialize(r)

	c.Assert(ok, Equals, true)

	phi := appendData(appendData(nil, []byte("sita@example.org")), []byte(gs.identity))

	t := append([]byte{}, 0x01)
	t = append(t, kdfx(usageReceiverClientProfile, 64, sita.clientProfile.serialize())...)
	t = append(t, kdfx(usageReceiverPrekeyCompositeIdentity, 64, gs.compositeIdentity())...)
	t = append(t, serializePoint(sita.i.pub.k)...)
	t = append(t, serializePoint(d2.s)...)
	t = append(t, kdfx(usageReceiverPrekeyCompositePHI, 64, phi)...)

	sigma, _ := generateSignature(gs, sita.longTerm.priv, sita.longTerm.pub, sita.longTerm.pub, gs.key.pub, &publicKey{d2.s}, t)

	sk := kdfx(usageSK, skLength, serializePoint(ed448.PointScalarMul(d2.s, sita.i.priv.k)))
	sitaBadPrekeyMacK := kdfx(usagePreMACKey, 64, sk)
	sitaBadPrekeyMacK[0] = 0xBA
	sitaBadPrekeyMacK[1] = 0xDB
	msg := generateStorageInformationRequestMessage(sitaBadPrekeyMacK)

	d3 := generateDake3(sita.instanceTag, sigma, msg.serialize())
	r, e = mh.handleMessage("sita@example.org", d3.serialize())

	c.Assert(e, Not(IsNil))
}

func (s *GenericServerSuite) Test_flow_publication(c *C) {
	stor := createInMemoryStorage()
	serverKey := deriveEDDSAKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        fixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.pub.fingerprint(),
		storageImpl: stor,
	}
	mh := &otrngMessageHandler{s: gs}
	gs.messageHandler = mh

	d1 := generateDake1(sita.instanceTag, sita.clientProfile, sita.i.pub.k)

	r, e := mh.handleMessage("sita@example.org", d1.serialize())

	c.Assert(e, IsNil)

	d2 := dake2Message{}
	_, ok := d2.deserialize(r)

	c.Assert(ok, Equals, true)

	phi := appendData(appendData(nil, []byte("sita@example.org")), []byte(gs.identity))

	t := append([]byte{}, 0x01)
	t = append(t, kdfx(usageReceiverClientProfile, 64, sita.clientProfile.serialize())...)
	t = append(t, kdfx(usageReceiverPrekeyCompositeIdentity, 64, gs.compositeIdentity())...)
	t = append(t, serializePoint(sita.i.pub.k)...)
	t = append(t, serializePoint(d2.s)...)
	t = append(t, kdfx(usageReceiverPrekeyCompositePHI, 64, phi)...)

	sigma, _ := generateSignature(gs, sita.longTerm.priv, sita.longTerm.pub, sita.longTerm.pub, gs.key.pub, &publicKey{d2.s}, t)

	sk := kdfx(usageSK, skLength, serializePoint(ed448.PointScalarMul(d2.s, sita.i.priv.k)))
	sitaPrekeyMacK := kdfx(usagePreMACKey, 64, sk)

	pp1, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)

	pm1, _ := generatePrekeyMessage(gs, sita.instanceTag)
	pm2, _ := generatePrekeyMessage(gs, sita.instanceTag)
	msg := generatePublicationMessage(sita.clientProfile, pp1, []*prekeyMessage{pm1, pm2}, sitaPrekeyMacK)

	d3 := generateDake3(sita.instanceTag, sigma, msg.serialize())

	r, e = mh.handleMessage("sita@example.org", d3.serialize())

	c.Assert(e, IsNil)

	res := &successMessage{}
	_, ok = res.deserialize(r)
	c.Assert(ok, Equals, true)
	c.Assert(res.instanceTag, Equals, sita.instanceTag)
	c.Assert(res.mac[:], DeepEquals, []byte{
		0xbf, 0xc5, 0xb6, 0x8d, 0xba, 0x66, 0xf9, 0x90,
		0x8d, 0x8b, 0xbc, 0xa1, 0x41, 0xf4, 0xe6, 0xc4,
		0xab, 0xa1, 0x1b, 0x58, 0x1b, 0xc4, 0x65, 0x12,
		0x14, 0x87, 0xbe, 0x3c, 0x24, 0x20, 0xa8, 0xf0,
		0x92, 0x89, 0x72, 0xcf, 0x54, 0x91, 0xfa, 0x5c,
		0x2b, 0xb9, 0xb4, 0x1b, 0xe5, 0xa6, 0x39, 0x93,
		0xa1, 0xbe, 0xf6, 0xe7, 0xea, 0x36, 0x9a, 0xad,
		0xf1, 0x12, 0xa4, 0x2f, 0x5a, 0xae, 0x39, 0xb,
	})

	entry := stor.perUser["sita@example.org"]
	c.Assert(entry, Not(IsNil))
	c.Assert(entry.clientProfiles[sita.instanceTag].Equals(sita.clientProfile), Equals, true)
	c.Assert(entry.prekeyProfiles[sita.instanceTag].Equals(pp1), Equals, true)
	c.Assert(entry.prekeyMessages[sita.instanceTag], HasLen, 2)
	c.Assert(entry.prekeyMessages[sita.instanceTag][0].Equals(pm1), Equals, true)
	c.Assert(entry.prekeyMessages[sita.instanceTag][1].Equals(pm2), Equals, true)
}

func (s *GenericServerSuite) Test_flow_retrieveEnsemblesFromKnownPerson(c *C) {
	serverKey := deriveEDDSAKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	stor := createInMemoryStorage()

	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        fixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.pub.fingerprint(),
		storageImpl: stor,
	}
	mh := &otrngMessageHandler{s: gs}

	stor.storeClientProfile("sita@example.org", sita.clientProfile)
	pp1, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	stor.storePrekeyProfile("sita@example.org", pp1)
	pm1, _ := generatePrekeyMessage(gs, sita.instanceTag)
	pm2, _ := generatePrekeyMessage(gs, sita.instanceTag)
	stor.storePrekeyMessages("sita@example.org", []*prekeyMessage{pm1, pm2})

	retM := &ensembleRetrievalQueryMessage{
		instanceTag: 0x5555DDDD,
		identity:    "sita@example.org",
		versions:    []byte{0x04},
	}

	r, e := mh.handleMessage("rama@example.org", retM.serialize())
	c.Assert(e, IsNil)

	rm := &ensembleRetrievalMessage{}
	_, ok := rm.deserialize(r)

	c.Assert(ok, Equals, true)
	c.Assert(rm.instanceTag, Equals, uint32(0x5555DDDD))

	c.Assert(stor.perUser["sita@example.org"].prekeyMessages[0x1245ABCD], HasLen, 1)
	c.Assert(stor.perUser["sita@example.org"].prekeyMessages[0x1245ABCD][0].Equals(pm2), Equals, true)
}
