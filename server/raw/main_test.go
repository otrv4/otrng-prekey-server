package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	. "gopkg.in/check.v1"
)

func (s *RawServerSuite) Test_main_printsErrorFromLoad(c *C) {
	flag.Parse()
	*keyFile = "/somewhere/that/shouldn't/work"
	capture := startStdoutCapture()
	defer capture.restore()

	main()

	c.Assert(capture.finish(), Equals,
		"encountered error when loading/creating keypair: open /somewhere/that/shouldn't/work: no such file or directory\n")
}

func (s *RawServerSuite) Test_main_printsErrorFromRun(c *C) {
	flag.Parse()
	*listenPort = 3242
	*keyFile = "raw-server.keys"
	*storageEngine = "in-memory"
	defer os.Remove(*keyFile)

	capture := startStdoutCapture()
	defer capture.restore()

	var l *net.TCPListener
	go func() {
		addr, _ := net.ResolveTCPAddr("tcp", net.JoinHostPort(*listenIP, fmt.Sprintf("%d", *listenPort)))
		l, _ = net.ListenTCP("tcp", addr)
	}()

	main()

	l.Close()

	c.Assert(capture.finish(), Equals,
		"Starting server on localhost:3242...\n"+
			"BBF1E0F815113A2E 016ADE9398D8CA6C C48DB33134F09918 A478A6CC98A9F0E7 A435962990B44512 5D1BC95FA9AA2D91 46BBC3F5061AE490\n"+
			"encountered error when running listener: listen tcp 127.0.0.1:3242: bind: address already in use\n",
	)
}

func (s *RawServerSuite) Test_main_shutsdownIfSigintIsSent(c *C) {
	flag.Parse()
	*listenPort = 3242
	*keyFile = "raw-server.keys"
	*storageEngine = "in-memory"
	defer os.Remove(*keyFile)

	capture := startStdoutCapture()
	defer capture.restore()

	ch := make(chan bool)

	go func() {
		main()
		ch <- true
	}()

	signalHandler <- os.Interrupt
	c.Assert(<-ch, Equals, true)
}
