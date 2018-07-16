package prekeyserver

import (
	"io/ioutil"
	"os"
	"path"
	"time"

	. "gopkg.in/check.v1"
)

const testDir = "__dir_for_tests"

// The sha256 for foo@example.org
const hexForUser1 = "D862FC5F7C662759FC6560B58153D3097852C10833045259C1B183A9AB59395A"

var prefixHexForUser1 = hexForUser1[0:4]

// The sha256 for someone@example.org
const hexForUser2 = "79A6123C2DB3B110C92F2872D217545DFC5FF5147BBDD47E67E72F223747A538"

var prefixHexForUser2 = hexForUser2[0:4]

// The sha256 for someoneElse@example.org
const hexForUser3 = "2B4DED05CD84F1430D50EB5ABB945576C14FEABF6820D8AFE06910328C3BD04F"

var prefixHexForUser3 = hexForUser3[0:4]

// The sha256 for someoneThird@example.org
const hexForUser4 = "97B01CE3DB56F98CA00BB4523337B12BA40D4D44A5CCD4B29EEAB288888D2F8D"

var prefixHexForUser4 = hexForUser4[0:4]

func (s *GenericServerSuite) Test_fileStorage_numberStored_returns0ForUnknownUser(c *C) {
	os.Mkdir(testDir, 0700)
	defer os.RemoveAll(testDir)

	fs := &fileStorage{path: testDir}
	c.Assert(fs.numberStored("foo@example.org", 0x11223344), Equals, uint32(0))
}

func (s *GenericServerSuite) Test_fileStorage_numberStored_returnsNumberOfPrekeyMessages(c *C) {
	os.Mkdir(testDir, 0700)
	defer os.RemoveAll(testDir)

	fsf, e := createFileStorageFactoryFrom("dir:" + testDir)
	c.Assert(e, IsNil)
	fs := fsf.createStorage()

	gs := &GenericServer{
		rand: fixtureRand(),
	}
	pm1, _ := generatePrekeyMessage(gs, sita.instanceTag)
	pm2, _ := generatePrekeyMessage(gs, sita.instanceTag)

	pmDir := path.Join(testDir, prefixHexForUser1, hexForUser1, "11223344", "pm")
	os.MkdirAll(pmDir, 0700)
	ioutil.WriteFile(path.Join(pmDir, formatUint32(pm1.identifier)+".bin"), pm1.serialize(), 0600)
	ioutil.WriteFile(path.Join(pmDir, formatUint32(pm2.identifier)+".bin"), pm2.serialize(), 0600)

	c.Assert(fs.numberStored("foo@example.org", 0x11223344), Equals, uint32(2))
}

func listDir(dir string) []os.FileInfo {
	v, _ := ioutil.ReadDir(dir)
	return v
}

func (s *GenericServerSuite) Test_fileStorage_cleanup_willRemoveExpiredClientProfiles(c *C) {
	os.Mkdir(testDir, 0700)
	defer os.RemoveAll(testDir)

	fsf, _ := createFileStorageFactoryFrom("dir:" + testDir)
	fs := fsf.createStorage()

	cp := generateSitaTestData().clientProfile
	cp.expiration = time.Date(2017, 11, 5, 13, 46, 00, 13, time.UTC)
	cp.sig = &eddsaSignature{s: cp.generateSignature(sita.longTerm)}

	cp2 := generateSitaTestData().clientProfile
	cp2.instanceTag = 0x42424242
	cp2.sig = &eddsaSignature{s: cp2.generateSignature(sita.longTerm)}

	fs.storeClientProfile("someone@example.org", cp)
	fs.storeClientProfile("someone@example.org", cp2)
	fs.storeClientProfile("someoneElse@example.org", sita.clientProfile)
	fs.storeClientProfile("someoneThird@example.org", cp)

	fs.cleanup()

	c.Assert(listDir(testDir), HasLen, 2)
	c.Assert(listDir(path.Join(testDir, prefixHexForUser2, hexForUser2)), HasLen, 1)
	c.Assert(entryExists(path.Join(testDir, prefixHexForUser2, hexForUser2, "42424242", "cp.bin")), Equals, true)
	c.Assert(listDir(path.Join(testDir, prefixHexForUser3, hexForUser3)), HasLen, 1)
	c.Assert(entryExists(path.Join(testDir, prefixHexForUser3, hexForUser3, "1245ABCD", "cp.bin")), Equals, true)
	c.Assert(entryExists(path.Join(testDir, prefixHexForUser4, hexForUser4)), Equals, false)
	c.Assert(entryExists(path.Join(testDir, prefixHexForUser4)), Equals, false)
}

func (s *GenericServerSuite) Test_fileStorage_cleanup_willRemoveExpiredPrekeyProfiles(c *C) {
	os.Mkdir(testDir, 0700)
	defer os.RemoveAll(testDir)

	gs := &GenericServer{
		rand: fixtureRand(),
	}

	fsf, _ := createFileStorageFactoryFrom("dir:" + testDir)
	fs := fsf.createStorage()

	pp1, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2017, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	pp2, _ := generatePrekeyProfile(gs, 0x42424242, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)

	fs.storePrekeyProfile("someone@example.org", pp1)
	fs.storePrekeyProfile("someone@example.org", pp2)
	fs.storePrekeyProfile("someoneElse@example.org", pp2)
	fs.storePrekeyProfile("someoneThird@example.org", pp1)

	fs.cleanup()

	c.Assert(listDir(testDir), HasLen, 2)
	c.Assert(listDir(path.Join(testDir, prefixHexForUser2, hexForUser2)), HasLen, 1)
	c.Assert(entryExists(path.Join(testDir, prefixHexForUser2, hexForUser2, "42424242", "pp.bin")), Equals, true)
	c.Assert(listDir(path.Join(testDir, prefixHexForUser3, hexForUser3)), HasLen, 1)
	c.Assert(entryExists(path.Join(testDir, prefixHexForUser3, hexForUser3, "42424242", "pp.bin")), Equals, true)
	c.Assert(entryExists(path.Join(testDir, prefixHexForUser4, hexForUser4)), Equals, false)
	c.Assert(entryExists(path.Join(testDir, prefixHexForUser4)), Equals, false)
}

func (s *GenericServerSuite) Test_fileStorage_cleanup_shouldNotRemoveUserIfThereArePrekeyMessages(c *C) {
	os.Mkdir(testDir, 0700)
	defer os.RemoveAll(testDir)

	gs := &GenericServer{
		rand: fixtureRand(),
	}

	fsf, _ := createFileStorageFactoryFrom("dir:" + testDir)
	fs := fsf.createStorage()

	pp1, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2017, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	pp2, _ := generatePrekeyProfile(gs, 0x42424242, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)

	pm1, _ := generatePrekeyMessage(gs, sita.instanceTag)

	fs.storePrekeyProfile("someone@example.org", pp1)
	fs.storePrekeyProfile("someone@example.org", pp2)
	fs.storePrekeyProfile("someoneElse@example.org", pp2)
	fs.storePrekeyProfile("someoneThird@example.org", pp1)

	fs.storePrekeyMessages("someoneThird@example.org", []*prekeyMessage{pm1})

	c.Assert(entryExists(path.Join(testDir, prefixHexForUser4, hexForUser4, "1245ABCD", "pp.bin")), Equals, true)

	fs.cleanup()

	c.Assert(listDir(testDir), HasLen, 3)
	c.Assert(listDir(path.Join(testDir, prefixHexForUser2, hexForUser2)), HasLen, 1)
	c.Assert(listDir(path.Join(testDir, prefixHexForUser3, hexForUser3)), HasLen, 1)
	c.Assert(entryExists(path.Join(testDir, prefixHexForUser4, hexForUser4, "1245ABCD", "pp.bin")), Equals, false)
	c.Assert(listDir(path.Join(testDir, prefixHexForUser4, hexForUser4, "1245ABCD", "pm")), HasLen, 1)
}

func (s *GenericServerSuite) Test_fileStorage_retrieveFor_willReturnAPrekeyEnsembleForEachInstanceTag(c *C) {
	os.Mkdir(testDir, 0700)
	defer os.RemoveAll(testDir)

	gs := &GenericServer{
		rand: fixtureRand(),
	}

	fsf, _ := createFileStorageFactoryFrom("dir:" + testDir)
	fs := fsf.createStorage()

	cp := generateSitaTestData().clientProfile
	cp2 := generateSitaTestData().clientProfile
	cp2.instanceTag = 0x42424242
	cp2.sig = &eddsaSignature{s: cp2.generateSignature(sita.longTerm)}

	pp1, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2029, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	pp2, _ := generatePrekeyProfile(gs, 0x42424242, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)

	pm1, _ := generatePrekeyMessage(gs, sita.instanceTag)
	pm2, _ := generatePrekeyMessage(gs, sita.instanceTag)
	pm3, _ := generatePrekeyMessage(gs, sita.instanceTag)
	pm4, _ := generatePrekeyMessage(gs, sita.instanceTag)

	pm2x1, _ := generatePrekeyMessage(gs, 0x42424242)
	pm2x2, _ := generatePrekeyMessage(gs, 0x42424242)
	pm2x3, _ := generatePrekeyMessage(gs, 0x42424242)

	fs.storeClientProfile("someone@example.org", cp)
	fs.storeClientProfile("someone@example.org", cp2)

	fs.storePrekeyProfile("someone@example.org", pp1)
	fs.storePrekeyProfile("someone@example.org", pp2)
	fs.storePrekeyMessages("someone@example.org", []*prekeyMessage{pm1, pm2, pm3, pm4})
	fs.storePrekeyMessages("someone@example.org", []*prekeyMessage{pm2x1, pm2x2, pm2x3})

	c.Assert(entryExists(path.Join(testDir, prefixHexForUser2, hexForUser2, "1245ABCD", "cp.bin")), Equals, true)
	c.Assert(entryExists(path.Join(testDir, prefixHexForUser2, hexForUser2, "42424242", "cp.bin")), Equals, true)
	c.Assert(entryExists(path.Join(testDir, prefixHexForUser2, hexForUser2, "1245ABCD", "pp.bin")), Equals, true)
	c.Assert(entryExists(path.Join(testDir, prefixHexForUser2, hexForUser2, "42424242", "pp.bin")), Equals, true)
	c.Assert(entryExists(path.Join(testDir, prefixHexForUser2, hexForUser2, "1245ABCD", "pm")), Equals, true)
	c.Assert(entryExists(path.Join(testDir, prefixHexForUser2, hexForUser2, "42424242", "pm")), Equals, true)
	c.Assert(listDir(path.Join(testDir, prefixHexForUser2, hexForUser2, "1245ABCD", "pm")), HasLen, 4)
	c.Assert(listDir(path.Join(testDir, prefixHexForUser2, hexForUser2, "42424242", "pm")), HasLen, 3)

	pes := fs.retrieveFor("someone@example.org")
	c.Assert(pes, HasLen, 2)
	c.Assert(pes[0].cp.identifier, DeepEquals, cp.identifier)
	c.Assert(pes[0].cp.sig, DeepEquals, cp.sig)
	c.Assert(pes[1].cp.identifier, DeepEquals, cp2.identifier)
	c.Assert(pes[1].cp.sig, DeepEquals, cp2.sig)
	c.Assert(pes[0].pp.identifier, DeepEquals, pp1.identifier)
	c.Assert(pes[0].pp.sig, DeepEquals, pp1.sig)
	c.Assert(pes[1].pp.identifier, DeepEquals, pp2.identifier)
	c.Assert(pes[1].pp.sig, DeepEquals, pp2.sig)
	c.Assert(pes[0].pm.identifier, DeepEquals, pm2.identifier)
	c.Assert(pes[0].pm.b, DeepEquals, pm2.b)
	c.Assert(pes[1].pm.identifier, DeepEquals, pm2x1.identifier)
	c.Assert(pes[1].pm.b, DeepEquals, pm2x1.b)

	c.Assert(listDir(testDir), HasLen, 1)
	c.Assert(listDir(path.Join(testDir, prefixHexForUser2, hexForUser2)), HasLen, 2)
	c.Assert(listDir(path.Join(testDir, prefixHexForUser2, hexForUser2, "1245ABCD", "pm")), HasLen, 3)
	c.Assert(listDir(path.Join(testDir, prefixHexForUser2, hexForUser2, "42424242", "pm")), HasLen, 2)

	pes = fs.retrieveFor("someone@example.org")
	c.Assert(pes, HasLen, 2)
	c.Assert(pes[0].pm.identifier, DeepEquals, pm3.identifier)
	c.Assert(pes[1].pm.identifier, DeepEquals, pm2x2.identifier)

	pes = fs.retrieveFor("someone@example.org")
	c.Assert(pes, HasLen, 2)
	c.Assert(pes[0].pm.identifier, DeepEquals, pm4.identifier)
	c.Assert(pes[1].pm.identifier, DeepEquals, pm2x3.identifier)

	pes = fs.retrieveFor("someone@example.org")
	c.Assert(pes, HasLen, 1)
	c.Assert(pes[0].pm.identifier, DeepEquals, pm1.identifier)

	pes = fs.retrieveFor("someone@example.org")
	c.Assert(pes, HasLen, 0)
}
