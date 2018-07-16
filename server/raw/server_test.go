package main

import (
	"crypto/rand"
	"errors"
	"io"
	"os"

	pks "github.com/otrv4/otrng-prekey-server"
	. "gopkg.in/check.v1"
)

func (s *RawServerSuite) Test_listenWith_willReturnAnErrorForAnInvalidAddressOrPort(c *C) {
	*listenIP = "localhost"
	*listenPort = 1234567
	rs := &rawServer{}
	e := rs.listenWith()
	c.Assert(e, ErrorMatches, "address 1234567: invalid port")
}

func (s *RawServerSuite) Test_listenWith_willReturnAnErrorForTryingToListenToAPortWeDontOwn(c *C) {
	*listenIP = "localhost"
	*listenPort = 80
	rs := &rawServer{}
	e := rs.listenWith()
	c.Assert(e, ErrorMatches, "listen tcp 127.0.0.1:80: bind: permission denied")
}

func (s *RawServerSuite) Test_run_willPassOnAnErrorFromListening(c *C) {
	capture := startStdoutCapture()
	defer capture.restore()
	*listenIP = "localhost"
	*listenPort = 80
	kp := pks.CreateFactory(rand.Reader).CreateKeypair()
	rs := &rawServer{kp: kp}
	e := rs.run()
	c.Assert(e, ErrorMatches, "encountered error when running listener: listen tcp 127.0.0.1:80: bind: permission denied")
}

type mockRWC struct {
	retReadN    int
	retReadE    error
	retReadBuf  []byte
	retWriteN   int
	retWriteE   error
	retCloseE   error
	readCalled  bool
	writeCalled bool
	closeCalled bool
}

func (m *mockRWC) Read(inp []byte) (int, error) {
	m.readCalled = true
	copy(inp, m.retReadBuf)
	return m.retReadN, m.retReadE
}

func (m *mockRWC) Write([]byte) (int, error) {
	m.writeCalled = true
	return m.retWriteN, m.retWriteE
}

func (m *mockRWC) Close() error {
	m.closeCalled = true
	return m.retCloseE
}

func (s *RawServerSuite) Test_handleRequest_willPrintErrorEncounteredWhenReading(c *C) {
	capture := startStdoutCapture()
	defer capture.restore()

	m := &mockRWC{retReadN: 0, retReadE: errors.New("something _absolutely_ horrific")}
	(&rawServer{}).handleRequest(m)
	c.Assert(m.readCalled, Equals, true)
	c.Assert(m.writeCalled, Equals, false)
	c.Assert(m.closeCalled, Equals, true)
	c.Assert(capture.finish(), Equals, "Encountered error when reading data: something _absolutely_ horrific\n")
}

func (s *RawServerSuite) Test_handleRequest_willPrintErrorEncounteredWhenProtocol(c *C) {
	capture := startStdoutCapture()
	defer capture.restore()

	m := &mockRWC{retReadN: 3, retReadE: io.EOF}
	m.retReadBuf = []byte{0x00, 0x05, 0x01}
	(&rawServer{}).handleRequest(m)
	c.Assert(m.readCalled, Equals, true)
	c.Assert(m.writeCalled, Equals, false)
	c.Assert(m.closeCalled, Equals, true)
	c.Assert(capture.finish(), Equals, "Encountered error when handling data: can't parse from element\n")
}

func (s *RawServerSuite) Test_handleRequest_willPrintErrorEncounteredWhenWriting(c *C) {
	capture := startStdoutCapture()
	defer capture.restore()

	m := &mockRWC{retReadN: 0, retReadE: io.EOF, retWriteN: 0, retWriteE: errors.New("something even worse")}
	(&rawServer{}).handleRequest(m)
	c.Assert(m.readCalled, Equals, true)
	c.Assert(m.writeCalled, Equals, true)
	c.Assert(m.closeCalled, Equals, true)
	c.Assert(capture.finish(), Equals, "Encountered error when writing data: something even worse\n")
}

func (s *RawServerSuite) Test_load_willReturnErrorEncounteredWithKeypair(c *C) {
	*keyFile = "/somewhere/that/shouldn't/work"
	fac := &mockFactory{}

	e := (&rawServer{}).load(fac)
	c.Assert(e, ErrorMatches, "encountered error when loading/creating keypair: open /somewhere/that/shouldn't/work: no such file or directory")
}

func (s *RawServerSuite) Test_load_willReturnErrorEncounteredWithStorageEngine(c *C) {
	*keyFile = "__test_thing_that_should_be_removed"
	*storageEngine = "--a-storage-engine-that-should-never-exist"
	defer os.Remove(*keyFile)
	e := (&rawServer{}).load(pks.CreateFactory(rand.Reader))
	c.Assert(e, ErrorMatches, "encountered error when creating storage engine: unknown storage type")
}

func (s *RawServerSuite) Test_run_willReturnNilOnControlledShutdown(c *C) {
	capture := startStdoutCapture()
	defer capture.restore()
	*listenIP = "localhost"
	*listenPort = 0
	kp := pks.CreateFactory(rand.Reader).CreateKeypair()
	rs := &rawServer{kp: kp}
	rs.finishRequested = true
	e := rs.run()
	c.Assert(e, IsNil)

}
