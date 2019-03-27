package main

import (
	"io/ioutil"
	"net"
	"time"

	"github.com/coyim/gotrax"
	pks "github.com/otrv4/otrng-prekey-server"
	. "gopkg.in/check.v1"
)

func (s *RawServerSuite) Test_flowTest_success(c *C) {
	capture := startStdoutCapture()
	defer capture.restore()

	rs := &rawServer{}
	e := rs.load(pks.CreateFactory(gotrax.FixtureRand()))
	c.Assert(e, IsNil)

	*listenIP = "localhost"
	*listenPort = 0
	go rs.run()

	for rs.l == nil {
		time.Sleep(time.Duration(10) * time.Millisecond)
	}

	a := rs.l.Addr().(*net.TCPAddr)
	con, _ := net.DialTCP(a.Network(), nil, a)
	defer con.Close()

	ensembleRetrievalQueryMessage := "AAQQEkRVEQAAABBzaXRhQGV4YW1wbGUub3JnAAAAAQQ=."
	expectedResult := "AAQOEkRVEQAAABBzaXRhQGV4YW1wbGUub3JnAAAALk5vIFByZWtleSBNZXNzYWdlcyBhdmFpbGFibGUgZm9yIHRoaXMgaWRlbnRpdHk=."
	from := "rama@example.org"

	toSend := []byte{}
	toSend = appendShort(toSend, uint16(len(from)))
	toSend = append(toSend, []byte(from)...)
	toSend = appendShort(toSend, uint16(len(ensembleRetrievalQueryMessage)))
	toSend = append(toSend, []byte(ensembleRetrievalQueryMessage)...)

	n, e := con.Write(toSend)
	c.Assert(e, IsNil)
	c.Assert(n, Equals, 65)
	con.CloseWrite()

	res, e := ioutil.ReadAll(con)
	c.Assert(e, IsNil)
	_, ss, _ := extractShort(res)
	c.Assert(ss, Equals, uint16(105))
	c.Assert(string(res[2:]), Equals, expectedResult)

	c.Assert(capture.finish(), Equals,
		"Starting server on localhost:0...\n"+
			"  [BBF1E0F815113A2E 016ADE9398D8CA6C C48DB33134F09918 A478A6CC98A9F0E7 A435962990B44512 5D1BC95FA9AA2D91 46BBC3F5061AE490]\n")

	rs.l.Close()
}
