package prekeyserver

import (
	"errors"
	"math/big"
	"time"

	"github.com/otrv4/ed448"
	"github.com/otrv4/gotrx"
	. "gopkg.in/check.v1"
)

func generateSitaClientProfile(longTerm *gotrx.Keypair, forgingKey *gotrx.Keypair) *gotrx.ClientProfile {
	sita := &gotrx.ClientProfile{}
	sita.InstanceTag = 0x1245ABCD
	sita.PublicKey = longTerm.Pub
	sita.ForgingKey = forgingKey.Pub
	sita.Versions = []byte{'4'}
	sita.Expiration = time.Date(2028, 11, 5, 13, 46, 00, 13, time.UTC)
	sita.DsaKey = nil
	sita.TransitionalSignature = nil
	sita.Sig = gotrx.CreateEddsaSignature([114]byte{
		0x54, 0x5a, 0x43, 0x79, 0xb1, 0xbe, 0x27,
		0xa0, 0x7d, 0xe2, 0x81, 0xbe, 0x20, 0x93,
		0x23, 0x30, 0xeb, 0x1b, 0x64, 0xbc, 0x05,
		0xe0, 0x70, 0x5b, 0x0d, 0x84, 0x1f, 0x06,
		0xbd, 0x5c, 0x48, 0x3d, 0xee, 0x06, 0x36,
		0xc5, 0x24, 0x1f, 0x31, 0x84, 0xcb, 0xd5,
		0xf6, 0x11, 0x2c, 0xdd, 0x7b, 0xc8, 0x00,
		0x33, 0x11, 0x08, 0x0c, 0xb2, 0xd7, 0xa7,
		0x00, 0xba, 0x16, 0xe7, 0x00, 0x4d, 0x9e,
		0x32, 0x09, 0x0b, 0x52, 0x88, 0xa4, 0x1f,
		0xa5, 0xcc, 0x2c, 0x2d, 0x28, 0x4f, 0xbc,
		0x82, 0xa0, 0x2f, 0x15, 0xcc, 0x16, 0xcd,
		0xc5, 0xd2, 0x5d, 0xc4, 0xa5, 0xc2, 0xd3,
		0xa9, 0xa9, 0x92, 0xac, 0x58, 0x5e, 0xd5,
		0x67, 0xde, 0x8b, 0x86, 0x7c, 0x9b, 0x06,
		0x8d, 0x69, 0xee, 0x2b, 0x7b, 0x03, 0xa5,
		0x2d, 0x0,
	})
	return sita
}

func generateSitaIPoint() *gotrx.Keypair {
	return gotrx.DeriveKeypair([symKeyLength]byte{0x42, 0x11, 0xCC, 0x22, 0xDD, 0x11, 0xFF})
}

type testData struct {
	instanceTag   uint32
	longTerm      *gotrx.Keypair
	forgingKey    *gotrx.Keypair
	clientProfile *gotrx.ClientProfile
	i             *gotrx.Keypair
}

func generateSitaTestData() *testData {
	t := &testData{}
	t.instanceTag = 0x1245ABCD
	t.longTerm = gotrx.DeriveKeypair([symKeyLength]byte{0x42, 0x00, 0x00, 0x55, 0x55, 0x00, 0x00, 0x55})
	t.forgingKey = gotrx.DeriveKeypair([symKeyLength]byte{0x55, 0x00, 0x00, 0x22, 0x33, 0x00, 0x00, 0x44})
	t.forgingKey.Pub = gotrx.CreatePublicKey(t.forgingKey.Pub.K(), gotrx.ForgingKey)
	t.clientProfile = generateSitaClientProfile(t.longTerm, t.forgingKey)
	t.i = generateSitaIPoint()
	return t
}

var sita = generateSitaTestData()

func (s *GenericServerSuite) Test_flow_CheckStorageNumber(c *C) {
	stor := createInMemoryStorage()
	serverKey := gotrx.DeriveKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        gotrx.FixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.Pub.Fingerprint(),
		storageImpl: stor,
		sessions:    newSessionManager(),
		rest:        nullRestrictor,
	}
	mh := &otrngMessageHandler{s: gs}
	gs.messageHandler = mh

	d1 := generateDake1(sita.instanceTag, sita.clientProfile, sita.i.Pub.K())

	r, e := mh.handleMessage("sita@example.org", d1.serialize())

	c.Assert(e, IsNil)

	d2 := dake2Message{}
	_, ok := d2.deserialize(r)

	c.Assert(ok, Equals, true)
	c.Assert(d2.instanceTag, Equals, uint32(0x1245ABCD))
	c.Assert(d2.serverIdentity, DeepEquals, []byte("masterOfKeys.example.org"))
	c.Assert(gotrx.SerializePoint(d2.serverKey), DeepEquals, []byte{
		0xaf, 0xde, 0x43, 0x7d, 0x1e, 0x80, 0xf8, 0x1a,
		0xb7, 0xfe, 0x5b, 0x21, 0x8c, 0x59, 0xa5, 0xff,
		0x5d, 0x7, 0xbb, 0xe1, 0xab, 0xe9, 0xc7, 0xaf,
		0xc3, 0x5b, 0x16, 0x54, 0x1c, 0x6a, 0xf2, 0x6c,
		0xc7, 0x6a, 0xa7, 0xba, 0xf5, 0xf0, 0x7e, 0x8b,
		0x26, 0x36, 0xe4, 0xe6, 0x66, 0x6b, 0x9f, 0x96,
		0xbd, 0x47, 0x0, 0xd4, 0xe6, 0x9f, 0x7, 0x9e,
		0x0,
	})
	c.Assert(d2.s.DSAEncode(), DeepEquals, []byte{
		0x6d, 0xf0, 0x8d, 0xf3, 0x8, 0x94, 0x3a, 0xa0,
		0xb6, 0xed, 0x29, 0xc0, 0xeb, 0xd2, 0x69, 0x74,
		0xa7, 0xb9, 0xcc, 0x53, 0x4, 0xea, 0xf8, 0x89,
		0x73, 0xa6, 0x35, 0x62, 0x6, 0xc5, 0xd3, 0x26,
		0x63, 0x90, 0xd8, 0x19, 0xb2, 0xf9, 0x84, 0xc8,
		0xb9, 0x66, 0x9d, 0x68, 0xea, 0x73, 0x2f, 0x9a,
		0x17, 0x91, 0x1d, 0xd2, 0x36, 0x77, 0x81, 0x6e,
		0x0,
	})

	c.Assert(d2.sigma.C1.Encode(), DeepEquals, []byte{
		0x3e, 0x4f, 0x9a, 0xe1, 0x98, 0x28, 0x67, 0x86,
		0xf1, 0xba, 0x33, 0x60, 0x31, 0x54, 0x50, 0x49,
		0x5, 0xfa, 0xc0, 0x93, 0xf5, 0x5d, 0x64, 0xca,
		0x22, 0x8d, 0x27, 0x22, 0x6c, 0xf6, 0x59, 0xd9,
		0xb3, 0x31, 0x31, 0x73, 0x10, 0xb4, 0x6e, 0xc6,
		0x17, 0xba, 0x5f, 0x91, 0xdd, 0x31, 0xb5, 0x9,
		0x83, 0x1, 0x51, 0x7c, 0x8, 0x2e, 0x1c, 0x33})

	c.Assert(d2.sigma.R1.Encode(), DeepEquals, []byte{
		0x47, 0x71, 0x5b, 0x81, 0xa8, 0x56, 0x47, 0x16,
		0x5, 0x8f, 0x9a, 0x2e, 0x9b, 0x2c, 0x55, 0xc3,
		0xd7, 0x0, 0xd3, 0x26, 0x13, 0xf5, 0x93, 0xe4,
		0xf4, 0xcb, 0x98, 0xb7, 0xe7, 0x81, 0xd, 0x35,
		0xa7, 0xa5, 0x59, 0x74, 0x9b, 0x7d, 0x19, 0x63,
		0x20, 0x5c, 0x1, 0x3b, 0x79, 0x70, 0x35, 0x33,
		0xfa, 0x1f, 0x38, 0xe3, 0x81, 0x96, 0x78, 0x2e})

	c.Assert(d2.sigma.C2.Encode(), DeepEquals, []byte{
		0x61, 0x9f, 0x94, 0x8c, 0x0a, 0x5b, 0xa4, 0xc4,
		0x38, 0xd2, 0x31, 0x48, 0xe7, 0xff, 0x29, 0x0d,
		0xb4, 0x85, 0x9c, 0xab, 0x99, 0x86, 0x36, 0x58,
		0x0d, 0x89, 0x9b, 0x71, 0xd1, 0xe3, 0x60, 0x31,
		0x17, 0x7c, 0x87, 0x68, 0x43, 0x0d, 0x75, 0x9a,
		0x9d, 0xde, 0x14, 0x4b, 0xba, 0x98, 0x7d, 0xee,
		0x4c, 0x52, 0xb0, 0x1b, 0xb3, 0x01, 0xb5, 0x1c,
	})

	c.Assert(d2.sigma.R2.Encode(), DeepEquals, []byte{
		0x96, 0xf4, 0x3a, 0x33, 0xfe, 0x63, 0x2f, 0x90,
		0x65, 0x27, 0x75, 0x52, 0xfa, 0x77, 0x9a, 0xea,
		0x56, 0xde, 0xc1, 0x50, 0x6b, 0x7c, 0x8a, 0x8b,
		0x60, 0x52, 0xdc, 0x5f, 0xfc, 0x60, 0xe1, 0x2e,
		0xa7, 0x27, 0xb9, 0x47, 0x79, 0xf4, 0x59, 0x2c,
		0x12, 0x07, 0xb5, 0x05, 0x88, 0x1b, 0x5d, 0xc4,
		0x89, 0x94, 0x9d, 0x60, 0xbe, 0x69, 0xd1, 0x32,
	})

	c.Assert(d2.sigma.C3.Encode(), DeepEquals, []byte{
		0x31, 0xb3, 0xc2, 0xa1, 0x10, 0x46, 0x2d, 0xd2,
		0x4a, 0x3c, 0x4d, 0x8c, 0x2c, 0xba, 0xd4, 0xe3,
		0x6e, 0x73, 0xfb, 0x8, 0x1f, 0x92, 0xb4, 0x88,
		0x85, 0x50, 0xd, 0xe4, 0x26, 0x9a, 0x3b, 0x86,
		0x94, 0x5a, 0xf3, 0x33, 0xb3, 0x95, 0x10, 0x6f,
		0x54, 0x6c, 0x14, 0xde, 0x51, 0x97, 0x14, 0x86,
		0x1f, 0xb0, 0x27, 0xdf, 0x57, 0x48, 0x7c, 0x3f})

	c.Assert(d2.sigma.R3.Encode(), DeepEquals, []byte{
		0x75, 0x8f, 0x53, 0x1c, 0x7b, 0x2f, 0x4, 0xbf,
		0x34, 0x16, 0xf0, 0x8e, 0x7, 0x19, 0x53, 0x9f,
		0x9c, 0xab, 0xcd, 0xab, 0xfa, 0x5f, 0x3a, 0xe3,
		0x55, 0xf5, 0x85, 0xbd, 0x3e, 0x46, 0x8b, 0xe,
		0xfb, 0x1a, 0xc, 0x1f, 0xa, 0xe3, 0x9e, 0x1e,
		0x93, 0x4a, 0x86, 0x95, 0x4c, 0x7, 0x0, 0xda,
		0xee, 0xd2, 0x8c, 0x4, 0xc0, 0x57, 0x71, 0x28})

	phi := gotrx.AppendData(gotrx.AppendData(nil, []byte("sita@example.org")), []byte(gs.identity))

	t := append([]byte{}, 0x01)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverClientProfile, 64, sita.clientProfile.Serialize())...)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverPrekeyCompositeIdentity, 64, gs.compositeIdentity())...)
	t = append(t, gotrx.SerializePoint(sita.i.Pub.K())...)
	t = append(t, gotrx.SerializePoint(d2.s)...)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverPrekeyCompositePHI, 64, phi)...)

	sigma, _ := gotrx.GenerateSignature(gs, sita.longTerm.Priv, sita.longTerm.Pub, sita.longTerm.Pub, gs.key.Pub, gotrx.CreatePublicKey(d2.s, gotrx.Ed448Key), t, gotrx.KdfPrekeyServer, usageAuth)

	sk := gotrx.KdfPrekeyServer(usageSK, skLength, gotrx.SerializePoint(ed448.PointScalarMul(d2.s, sita.i.Priv.K())))
	sitaPrekeyMac := gotrx.KdfPrekeyServer(usagePreMACKey, 64, sk)
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
		0x46, 0xfe, 0x33, 0x92, 0xb8, 0xfb, 0xfa, 0x64,
		0x1a, 0xef, 0x32, 0xec, 0xbc, 0x4c, 0x88, 0x82,
		0xb5, 0x5e, 0xc, 0x34, 0x28, 0x6b, 0x6, 0x77,
		0x58, 0x5b, 0xc4, 0x61, 0x30, 0x40, 0xbe, 0x97,
		0x10, 0xfc, 0x24, 0x71, 0xd1, 0xf3, 0x19, 0x19,
		0x4d, 0xc3, 0x20, 0x4c, 0xcd, 0x78, 0x21, 0xc6,
		0x60, 0xce, 0xbd, 0xc3, 0xd6, 0x67, 0xb8, 0x2a,
		0x85, 0x16, 0x70, 0x92, 0x45, 0x43, 0x71, 0x22,
	})
}

func (s *GenericServerSuite) Test_flow_retrieveEnsemblesFromUnknownPerson(c *C) {
	stor := createInMemoryStorage()
	retM := &ensembleRetrievalQueryMessage{
		instanceTag: 0x12445511,
		identity:    "sita@example.org",
		versions:    []byte{0x04},
	}

	serverKey := gotrx.DeriveKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        gotrx.FixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.Pub.Fingerprint(),
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
	serverKey := gotrx.DeriveKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        gotrx.FixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.Pub.Fingerprint(),
		rest:        nullRestrictor,
	}
	mh := &otrngMessageHandler{s: gs}

	badcp := generateSitaClientProfile(sita.longTerm, sita.forgingKey)
	badcp.InstanceTag = 0x42424242

	d1 := generateDake1(sita.instanceTag, badcp, sita.i.Pub.K())

	_, e := mh.handleMessage("sita@example.org", d1.serialize())

	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid client profile"))
}

func (s *GenericServerSuite) Test_flow_invalidPointI(c *C) {
	serverKey := gotrx.DeriveKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        gotrx.FixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.Pub.Fingerprint(),
		rest:        nullRestrictor,
	}
	mh := &otrngMessageHandler{s: gs}

	badcp := generateSitaClientProfile(sita.longTerm, sita.forgingKey)
	badi := ed448.NewPoint([16]uint32{0x00}, [16]uint32{0x01}, [16]uint32{0x01}, [16]uint32{0x00})
	d1 := generateDake1(sita.instanceTag, badcp, badi)

	_, e := mh.handleMessage("sita@example.org", d1.serialize())

	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid point I"))
}

func (s *GenericServerSuite) Test_flow_invalidDAKE3(c *C) {
	serverKey := gotrx.DeriveKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        gotrx.FixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.Pub.Fingerprint(),
		sessions:    newSessionManager(),
		rest:        nullRestrictor,
	}
	mh := &otrngMessageHandler{s: gs}

	d1 := generateDake1(sita.instanceTag, sita.clientProfile, sita.i.Pub.K())

	r, e := mh.handleMessage("sita@example.org", d1.serialize())

	c.Assert(e, IsNil)

	d2 := dake2Message{}
	_, ok := d2.deserialize(r)

	c.Assert(ok, Equals, true)

	phi := gotrx.AppendData(gotrx.AppendData(nil, []byte("sita@example.org")), []byte(gs.identity))

	t := append([]byte{}, 0x01)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverClientProfile, 64, sita.clientProfile.Serialize())...)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverPrekeyCompositeIdentity, 64, gs.compositeIdentity())...)
	t = append(t, gotrx.SerializePoint(sita.i.Pub.K())...)
	t = append(t, gotrx.SerializePoint(d2.s)...)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverPrekeyCompositePHI, 64, phi)...)

	sigma, _ := gotrx.GenerateSignature(gs, sita.longTerm.Priv, sita.longTerm.Pub, sita.longTerm.Pub, gs.key.Pub, gotrx.CreatePublicKey(d2.s, gotrx.Ed448Key), t, gotrx.KdfPrekeyServer, usageAuth)

	sk := gotrx.KdfPrekeyServer(usageSK, skLength, gotrx.SerializePoint(ed448.PointScalarMul(d2.s, sita.i.Priv.K())))
	sitaPrekeyMac := gotrx.KdfPrekeyServer(usagePreMACKey, 64, sk)
	msg := generateStorageInformationRequestMessage(sitaPrekeyMac)

	d3 := generateDake3(0xBADBADBA, sigma, msg.serialize())
	r, e = mh.handleMessage("sita@example.org", d3.serialize())

	c.Assert(e, Not(IsNil))
}

func (s *GenericServerSuite) Test_flow_invalidMACused(c *C) {
	serverKey := gotrx.DeriveKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        gotrx.FixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.Pub.Fingerprint(),
		sessions:    newSessionManager(),
		rest:        nullRestrictor,
	}
	mh := &otrngMessageHandler{s: gs}
	gs.messageHandler = mh

	d1 := generateDake1(sita.instanceTag, sita.clientProfile, sita.i.Pub.K())

	r, e := mh.handleMessage("sita@example.org", d1.serialize())

	c.Assert(e, IsNil)

	d2 := dake2Message{}
	_, ok := d2.deserialize(r)

	c.Assert(ok, Equals, true)

	phi := gotrx.AppendData(gotrx.AppendData(nil, []byte("sita@example.org")), []byte(gs.identity))

	t := append([]byte{}, 0x01)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverClientProfile, 64, sita.clientProfile.Serialize())...)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverPrekeyCompositeIdentity, 64, gs.compositeIdentity())...)
	t = append(t, gotrx.SerializePoint(sita.i.Pub.K())...)
	t = append(t, gotrx.SerializePoint(d2.s)...)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverPrekeyCompositePHI, 64, phi)...)

	sigma, _ := gotrx.GenerateSignature(gs, sita.longTerm.Priv, sita.longTerm.Pub, sita.longTerm.Pub, gs.key.Pub, gotrx.CreatePublicKey(d2.s, gotrx.Ed448Key), t, gotrx.KdfPrekeyServer, usageAuth)

	sk := gotrx.KdfPrekeyServer(usageSK, skLength, gotrx.SerializePoint(ed448.PointScalarMul(d2.s, sita.i.Priv.K())))
	sitaBadPrekeyMacK := gotrx.KdfPrekeyServer(usagePreMACKey, 64, sk)
	sitaBadPrekeyMacK[0] = 0xBA
	sitaBadPrekeyMacK[1] = 0xDB
	msg := generateStorageInformationRequestMessage(sitaBadPrekeyMacK)

	d3 := generateDake3(sita.instanceTag, sigma, msg.serialize())
	r, e = mh.handleMessage("sita@example.org", d3.serialize())

	c.Assert(e, Not(IsNil))
}

func (s *GenericServerSuite) Test_flow_publication(c *C) {
	stor := createInMemoryStorage()
	serverKey := gotrx.DeriveKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        gotrx.FixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.Pub.Fingerprint(),
		storageImpl: stor,
		sessions:    newSessionManager(),
		rest:        nullRestrictor,
	}
	mh := &otrngMessageHandler{s: gs}
	gs.messageHandler = mh

	d1 := generateDake1(sita.instanceTag, sita.clientProfile, sita.i.Pub.K())

	r, e := mh.handleMessage("sita@example.org", d1.serialize())

	c.Assert(e, IsNil)

	d2 := dake2Message{}
	_, ok := d2.deserialize(r)

	c.Assert(ok, Equals, true)

	phi := gotrx.AppendData(gotrx.AppendData(nil, []byte("sita@example.org")), []byte(gs.identity))

	t := append([]byte{}, 0x01)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverClientProfile, 64, sita.clientProfile.Serialize())...)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverPrekeyCompositeIdentity, 64, gs.compositeIdentity())...)
	t = append(t, gotrx.SerializePoint(sita.i.Pub.K())...)
	t = append(t, gotrx.SerializePoint(d2.s)...)
	t = append(t, gotrx.KdfPrekeyServer(usageReceiverPrekeyCompositePHI, 64, phi)...)

	sigma, _ := gotrx.GenerateSignature(gs, sita.longTerm.Priv, sita.longTerm.Pub, sita.longTerm.Pub, gs.key.Pub, gotrx.CreatePublicKey(d2.s, gotrx.Ed448Key), t, gotrx.KdfPrekeyServer, usageAuth)

	sk := gotrx.KdfPrekeyServer(usageSK, skLength, gotrx.SerializePoint(ed448.PointScalarMul(d2.s, sita.i.Priv.K())))
	sitaPrekeyMacK := gotrx.KdfPrekeyServer(usagePreMACKey, 64, sk)

	pp1, ppk1 := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)

	pm1, pmk1, pmbpriv1, pmbpub1 := generatePrekeyMessage(gs, sita.instanceTag)
	pm2, pmk2, pmbpriv2, pmbpub2 := generatePrekeyMessage(gs, sita.instanceTag)

	prof1, prof2 := generatePrekeyMessagesProofs(gs, []*gotrx.Keypair{pmk1, pmk2}, []*big.Int{pmbpriv1, pmbpriv2}, []*big.Int{pmbpub1, pmbpub2}, sk)
	prof3 := gemeratePrekeyProfileProof(gs, ppk1, sk)

	msg := generatePublicationMessage(sita.clientProfile, pp1, []*prekeyMessage{pm1, pm2}, prof1, prof2, prof3, sitaPrekeyMacK)

	d3 := generateDake3(sita.instanceTag, sigma, msg.serialize())

	r, e = mh.handleMessage("sita@example.org", d3.serialize())

	c.Assert(e, IsNil)

	res := &successMessage{}
	_, ok = res.deserialize(r)
	c.Assert(ok, Equals, true)
	c.Assert(res.instanceTag, Equals, sita.instanceTag)
	c.Assert(res.mac[:], DeepEquals, []byte{
		0xf2, 0xe4, 0xdc, 0x13, 0x4e, 0xd6, 0x7c, 0xa6,
		0x52, 0xc7, 0x1f, 0x68, 0x61, 0xb, 0x2b, 0x14,
		0xd2, 0xea, 0xc9, 0x42, 0xf2, 0xa1, 0xf9, 0x76,
		0x25, 0xa3, 0x24, 0x13, 0x5e, 0x15, 0x4a, 0x83,
		0xf0, 0x7d, 0x2d, 0x2a, 0x24, 0x9, 0xca, 0x63,
		0xf7, 0xa4, 0xde, 0xc5, 0xf9, 0x2, 0x76, 0x52,
		0xa4, 0xb, 0xe3, 0x31, 0xc7, 0x4e, 0x41, 0x4a,
		0x27, 0x9d, 0x48, 0xec, 0xc3, 0x1b, 0x38, 0x6c,
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
	serverKey := gotrx.DeriveKeypair([symKeyLength]byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25})
	stor := createInMemoryStorage()

	gs := &GenericServer{
		identity:    "masterOfKeys.example.org",
		rand:        gotrx.FixtureRand(),
		key:         serverKey,
		fingerprint: serverKey.Pub.Fingerprint(),
		storageImpl: stor,
	}
	mh := &otrngMessageHandler{s: gs}

	stor.storeClientProfile("sita@example.org", sita.clientProfile)
	pp1, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	stor.storePrekeyProfile("sita@example.org", pp1)
	pm1, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
	pm2, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
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
