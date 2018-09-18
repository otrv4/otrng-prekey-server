package prekeyserver

import (
	"io/ioutil"
	"os"
	"path"
	"time"

	"github.com/coyim/gotrax"
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
		rand: gotrax.FixtureRand(),
	}
	pm1, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
	pm2, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)

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
	cp.Expiration = time.Date(2017, 11, 5, 13, 46, 00, 13, time.UTC)
	cp.Sig = gotrax.CreateEddsaSignature(cp.GenerateSignature(sita.longTerm))

	cp2 := generateSitaTestData().clientProfile
	cp2.InstanceTag = 0x42424242
	cp2.Sig = gotrax.CreateEddsaSignature(cp2.GenerateSignature(sita.longTerm))

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
		rand: gotrax.FixtureRand(),
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
		rand: gotrax.FixtureRand(),
	}

	fsf, _ := createFileStorageFactoryFrom("dir:" + testDir)
	fs := fsf.createStorage()

	pp1, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2017, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	pp2, _ := generatePrekeyProfile(gs, 0x42424242, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)

	pm1, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)

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
		rand: gotrax.FixtureRand(),
	}

	fsf, _ := createFileStorageFactoryFrom("dir:" + testDir)
	fs := fsf.createStorage()

	cp := generateSitaTestData().clientProfile
	cp2 := generateSitaTestData().clientProfile
	cp2.InstanceTag = 0x42424242
	cp2.Sig = gotrax.CreateEddsaSignature(cp2.GenerateSignature(sita.longTerm))

	pp1, _ := generatePrekeyProfile(gs, sita.instanceTag, time.Date(2029, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)
	pp2, _ := generatePrekeyProfile(gs, 0x42424242, time.Date(2028, 11, 5, 4, 46, 00, 13, time.UTC), sita.longTerm)

	pm1, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
	pm2, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
	pm3, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
	pm4, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)

	pm2x1, _, _, _ := generatePrekeyMessage(gs, 0x42424242)
	pm2x2, _, _, _ := generatePrekeyMessage(gs, 0x42424242)
	pm2x3, _, _, _ := generatePrekeyMessage(gs, 0x42424242)

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
	c.Assert(pes[0].cp.Sig, DeepEquals, cp.Sig)
	c.Assert(pes[1].cp.Sig, DeepEquals, cp2.Sig)
	c.Assert(pes[0].pp.sig, DeepEquals, pp1.sig)
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

	c.Assert(entryExists(path.Join(testDir, prefixHexForUser2, hexForUser2, "1245ABCD", "pm")), Equals, true)
	fs.cleanup()
	c.Assert(entryExists(path.Join(testDir, prefixHexForUser2, hexForUser2, "1245ABCD", "pm")), Equals, false)
}

func (s *GenericServerSuite) Test_fileStorage_storePrekeyMessages_reportsErrorWhenItCantWriteToTheDirectory(c *C) {
	os.Mkdir(testDir, 0700)
	defer os.RemoveAll(testDir)

	gs := &GenericServer{
		rand: gotrax.FixtureRand(),
	}

	fsf, _ := createFileStorageFactoryFrom("dir:" + testDir)
	fs := fsf.createStorage()

	os.MkdirAll(path.Join(testDir, prefixHexForUser2, hexForUser2, "1245ABCD"), 0700)
	os.Mkdir(path.Join(testDir, prefixHexForUser2, hexForUser2, "1245ABCD", "pm"), 0500)

	pm1, _, _, _ := generatePrekeyMessage(gs, sita.instanceTag)
	e := fs.storePrekeyMessages("someone@example.org", []*prekeyMessage{pm1})
	c.Assert(e, ErrorMatches, "open __dir_for_tests/79A6/79A6123C2DB3B110C92F2872D217545DFC5FF5147BBDD47E67E72F223747A538/1245ABCD/pm/ABCDABCD.bin: permission denied")
}

func (s *GenericServerSuite) Test_fileStorage_numberStored_returns0WhenItCantReadThePmDir(c *C) {
	os.Mkdir(testDir, 0700)
	defer os.RemoveAll(testDir)

	fsf, _ := createFileStorageFactoryFrom("dir:" + testDir)
	fs := fsf.createStorage()

	os.MkdirAll(path.Join(testDir, prefixHexForUser2, hexForUser2, "1245ABCD"), 0700)
	res := fs.numberStored("someone@example.org", 0x1245ABCD)
	c.Assert(res, Equals, uint32(0))
}

func (s *GenericServerSuite) Test_fileStorage_retrieveFor_returnsEmptyForNonExistantUser(c *C) {
	os.Mkdir(testDir, 0700)
	defer os.RemoveAll(testDir)

	fsf, _ := createFileStorageFactoryFrom("dir:" + testDir)
	fs := fsf.createStorage()

	res := fs.retrieveFor("someone@example.org")
	c.Assert(res, HasLen, 0)
}

func (s *GenericServerSuite) Test_fileStorage_retrieveFor_returnsEmptyIfItCantReadDirectory(c *C) {
	os.Mkdir(testDir, 0700)
	defer os.RemoveAll(testDir)

	fsf, _ := createFileStorageFactoryFrom("dir:" + testDir)
	fs := fsf.createStorage()

	os.Mkdir(path.Join(testDir, prefixHexForUser2), 0700)
	os.Mkdir(path.Join(testDir, prefixHexForUser2, hexForUser2), 0000)
	res := fs.retrieveFor("someone@example.org")
	c.Assert(res, HasLen, 0)
}

func (s *GenericServerSuite) Test_fileStorage_listDirsIn_returnsEmptyIfItCantReadDirectory(c *C) {
	os.Mkdir(testDir, 0600)
	defer os.RemoveAll(testDir)

	c.Assert(listDirsIn(testDir), HasLen, 0)
}

func (s *GenericServerSuite) Test_fileStorage_listInstanceTagsIn_returnsEmptyIfItCantReadDirectory(c *C) {
	os.Mkdir(testDir, 0600)
	defer os.RemoveAll(testDir)

	c.Assert(listInstanceTagsIn(testDir), HasLen, 0)
}

func (s *GenericServerSuite) Test_fileStorage_cleanupClientProfile_returnsErrorIfItCantReadTheFile(c *C) {
	os.Mkdir(testDir, 0600)
	defer os.RemoveAll(testDir)

	ioutil.WriteFile(path.Join(testDir, "cp.bin"), []byte{}, 0200)

	c.Assert(cleanupClientProfile(testDir), ErrorMatches, "open __dir_for_tests/cp.bin: permission denied")
}

func (s *GenericServerSuite) Test_fileStorage_cleanupPrekeyProfile_returnsErrorIfItCantReadTheFile(c *C) {
	os.Mkdir(testDir, 0600)
	defer os.RemoveAll(testDir)

	ioutil.WriteFile(path.Join(testDir, "pp.bin"), []byte{}, 0200)

	c.Assert(cleanupPrekeyProfile(testDir), ErrorMatches, "open __dir_for_tests/pp.bin: permission denied")
}
