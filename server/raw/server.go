package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"time"

	pks "github.com/otrv4/otrng-prekey-server"
)

// TODO: add a sigint / ctrl-c handler that shuts down everything properly

// This implements the TCP network protocol for talking to
// the prekey server. The format follows what's documented
// in protocol.go
// In general, the server expects a connection to first write
// all its data, and then close the write pipe - the processing
// will only happen after we have reached EOF from the other side.

type rawServer struct {
	s               pks.Server
	l               *net.TCPListener
	kp              pks.Keypair
	finishRequested bool
}

func (rs *rawServer) load(f pks.Factory) error {
	var e error
	rs.kp, e = loadOrCreateKeypair(f)
	if e != nil {
		return fmt.Errorf("encountered error when loading/creating keypair: %v", e)
	}
	storage, e := f.LoadStorageType(*storageEngine)
	if e != nil {
		return fmt.Errorf("encountered error when creating storage engine: %v", e)
	}
	server := f.NewServer(*serverIdentity,
		rs.kp,
		int(*fragLen),
		storage,
		time.Duration(*sessionTimeout)*time.Minute,
		time.Duration(*fragmentationTimeout)*time.Minute)

	rs.s = server

	return nil
}

func (rs *rawServer) run() error {
	fmt.Printf("Starting server on %s...\n", net.JoinHostPort(*listenIP, fmt.Sprintf("%d", *listenPort)))
	fmt.Printf("  [%s]\n", formatFingerprint(rs.kp.Fingerprint()))

	if e := rs.listenWith(); e != nil {
		return fmt.Errorf("encountered error when running listener: %v", e)
	}
	return nil
}

func (rs *rawServer) listenWith() error {
	addr, e := net.ResolveTCPAddr("tcp", net.JoinHostPort(*listenIP, fmt.Sprintf("%d", *listenPort)))
	if e != nil {
		return e
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}
	l.SetDeadline(time.Now().Add(time.Duration(100) * time.Millisecond))
	rs.l = l
	defer rs.l.Close()
	for !rs.finishRequested {
		conn, err := rs.l.Accept()
		if err == nil {
			go rs.handleRequest(conn)
		} else {
			te, ok := err.(net.Error)
			if !ok || !te.Timeout() {
				return err
			}
		}
	}
	return nil
}

func (rs *rawServer) handleRequest(c io.ReadWriteCloser) {
	defer c.Close()
	data, e := ioutil.ReadAll(c)
	if e != nil {
		fmt.Printf("Encountered error when reading data: %v\n", e)
		return
	}
	res, e := protocolHandleData(data, rs.s)
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
