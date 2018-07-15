package main

import (
	"errors"
	"io"
	"io/ioutil"
	"os"
	"time"

	pks "github.com/otrv4/otrng-prekey-server"
	. "gopkg.in/check.v1"
)

func (s *RawServerSuite) Test_formatFingerprint_willFormatTheFingerprint(c *C) {
	d := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x11, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x21, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x31, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x41, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x51, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x61, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	}
	c.Assert(formatFingerprint(d), Equals, "0102030405060708 1102030405060708 2102030405060708 3102030405060708 4102030405060708 5102030405060708 6102030405060708")
}

type mockFactory struct {
	loadKeypairFromArgFileName string
	loadKeypairFromReturn      pks.Keypair
	loadKeypairFromReturnError error
}

func (f *mockFactory) CreateKeypair() pks.Keypair {
	return nil
}

func (f *mockFactory) LoadKeypairFrom(r io.Reader) (pks.Keypair, error) {
	ff := r.(*os.File)
	f.loadKeypairFromArgFileName = ff.Name()
	return f.loadKeypairFromReturn, f.loadKeypairFromReturnError
}

func (f *mockFactory) LoadStorageType(name string) (pks.Storage, error) {
	return nil, nil
}

func (f *mockFactory) NewServer(string, pks.Keypair, int, pks.Storage, time.Duration, time.Duration) pks.Server {
	return nil
}

func (s *RawServerSuite) Test_loadOrCreateKeypair_willTryToLoadFromAnExistingFile(c *C) {
	f, _ := ioutil.TempFile("", "otrng-raw-createkeypair-file")
	defer os.Remove(f.Name())
	f.Close()
	*keyFile = f.Name()

	fac := &mockFactory{}
	_, e := loadOrCreateKeypair(fac)
	c.Assert(e, IsNil)
	c.Assert(fac.loadKeypairFromArgFileName, Equals, f.Name())
}

func (s *RawServerSuite) Test_loadOrCreateKeypair_willReturnErrorIfSomethingGoesWrongWithFile(c *C) {
	f, _ := ioutil.TempFile("", "otrng-raw-createkeypair-file")
	f.Close()
	os.Chmod(f.Name(), 0200)
	defer os.Remove(f.Name())
	*keyFile = f.Name()

	fac := &mockFactory{}
	_, e := loadOrCreateKeypair(fac)
	c.Assert(e, ErrorMatches, ".* permission denied")
}

func (s *RawServerSuite) Test_loadOrCreateKeypair_returnsErrorFromLoadingOfKeypair(c *C) {
	f, _ := ioutil.TempFile("", "otrng-raw-createkeypair-file")
	defer os.Remove(f.Name())
	f.Close()
	*keyFile = f.Name()

	fac := &mockFactory{
		loadKeypairFromReturnError: errors.New("something blah"),
	}
	_, e := loadOrCreateKeypair(fac)
	c.Assert(e, ErrorMatches, "something blah")
}

func (s *RawServerSuite) Test_loadOrCreateKeypair_returnsErrorIfFileCantBeCreated(c *C) {
	*keyFile = "/somewhere/that/shouldn't/work"

	fac := &mockFactory{}
	_, e := loadOrCreateKeypair(fac)
	c.Assert(e, ErrorMatches, "open /somewhere/that/shouldn't/work: no such file or directory")
}

func (s *RawServerSuite) Test_loadOrCreateKeypair_writesANewlyCreatedKeypairToTheFile(c *C) {
	fn := "__test_file_for_keys"
	defer os.Remove(fn)
	*keyFile = fn
	f := pks.CreateFactory(nil)
	c.Assert(fileExists(fn), Equals, false)
	r, e := loadOrCreateKeypair(f)
	c.Assert(e, IsNil)
	c.Assert(fileExists(fn), Equals, true)

	r2, e2 := loadOrCreateKeypair(f)
	c.Assert(e2, IsNil)
	c.Assert(r.Fingerprint(), DeepEquals, r2.Fingerprint())
}
