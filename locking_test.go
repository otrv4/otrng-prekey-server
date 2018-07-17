package prekeyserver

import (
	"encoding/binary"
	"io/ioutil"
	"os"
	"path"
	"time"

	. "gopkg.in/check.v1"
)

func (s *GenericServerSuite) Test_fileStorage_lockDir_unlockDir_worksCorrectlyInSimpleCase(c *C) {
	os.Mkdir(testDir, 0700)
	defer os.RemoveAll(testDir)

	t1 := lockDir(testDir)

	c.Assert(entryExists(path.Join(testDir, ".lock")), Equals, true)
	b, _ := ioutil.ReadFile(path.Join(testDir, ".lock"))
	c.Assert(binary.BigEndian.Uint64(b), Equals, t1)

	unlockDir(testDir, t1)
	c.Assert(entryExists(path.Join(testDir, ".lock")), Equals, false)
}

func (s *GenericServerSuite) Test_fileStorage_lockDir_waitsUntilAbleToLockIfSomeoneAlreadyLockedFile(c *C) {
	os.Mkdir(testDir, 0700)
	defer os.RemoveAll(testDir)

	lfile := path.Join(testDir, ".lock")

	ioutil.WriteFile(lfile, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, 0600)
	var ackLock time.Time

	wait := make(chan bool)

	go func() {
		t1 := lockDir(testDir)
		ackLock = time.Now()
		c.Assert(entryExists(lfile), Equals, true)
		b, _ := ioutil.ReadFile(lfile)
		c.Assert(binary.BigEndian.Uint64(b), Equals, t1)
		unlockDir(testDir, t1)
		c.Assert(entryExists(lfile), Equals, false)
		wait <- true
	}()

	before := time.Now()
	time.Sleep(time.Duration(100) * time.Millisecond)
	os.Remove(lfile)
	<-wait
	c.Assert(before.Before(ackLock), Equals, true)
}

func (s *GenericServerSuite) Test_fileStorage_unlockDir_doesntRemoveALockForAnotherToken(c *C) {
	os.Mkdir(testDir, 0700)
	defer os.RemoveAll(testDir)

	lfile := path.Join(testDir, ".lock")

	ioutil.WriteFile(lfile, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, 0600)

	unlockDir(testDir, 0x4242424212341123)

	c.Assert(entryExists(lfile), Equals, true)
}
