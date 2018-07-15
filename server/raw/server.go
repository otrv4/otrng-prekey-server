package main

import (
	"fmt"
	"io/ioutil"
	"net"

	pks "github.com/otrv4/otrng-prekey-server"
)

func listenWith(s pks.Server) error {
	l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", *listenIP, *listenPort))
	if err != nil {
		return err
	}
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go handleRequest(conn, s)
	}
}

func handleRequest(c net.Conn, s pks.Server) {
	defer c.Close()
	data, e := ioutil.ReadAll(c)
	if e != nil {
		fmt.Printf("Encountered error when reading data: %v\n", e)
		return
	}
	res, e := protocolHandleData(data, s)
	if e != nil {
		fmt.Printf("Encountered error when handling data: %v\n", e)
		return
	}
	_, e = c.Write(res)
	if e != nil {
		fmt.Printf("Encountered error when writing data: %v\n", e)
		return
	}
}
