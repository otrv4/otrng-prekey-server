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
			"  [3B72D580C05DE282 3A14B02B682636BF 58F291A7E831D237 ECE8FC14DA50A187 A50ACF665442AB2D 140E140B813CFCCA 993BC02AA4A3D35C]\n"+
			"encountered error when running listener: listen tcp 127.0.0.1:3242: bind: address already in use\n",
	)

}
