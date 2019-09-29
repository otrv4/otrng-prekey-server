package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"sync"
	"time"

	pks "github.com/otrv4/otrng-prekey-server"
)

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
	activeConns     sync.WaitGroup
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
		time.Duration(*fragmentationTimeout)*time.Minute,
		commandLineRestrictor)

	rs.s = server

	return nil
}

func (rs *rawServer) run() error {
	fmt.Printf("Starting server on %s...\n", net.JoinHostPort(*listenIP, fmt.Sprintf("%d", *listenPort)))
	fmt.Printf("%s\n", formatFingerprint(rs.kp.Fingerprint()))

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
	rs.l = l
	defer rs.l.Close()
	for !rs.finishRequested {
		l.SetDeadline(time.Now().Add(time.Duration(100) * time.Millisecond))
		conn, err := rs.l.Accept()
		if err == nil {
			conn.SetDeadline(time.Now().Add(time.Duration(2) * time.Minute))
			go rs.handleRequest(conn)
		} else {
			if te, ok := err.(net.Error); !ok || !te.Timeout() {
				return err
			}
		}
	}
	return nil
}

const readLimit = 268435456 // 2 ** 28 ~ 268 Mb

func (rs *rawServer) handleRequest(c io.ReadWriteCloser) {
	rs.activeConns.Add(1)
	defer rs.activeConns.Done()
	defer c.Close()
	data, e := ioutil.ReadAll(io.LimitReader(c, readLimit))
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

func (rs *rawServer) shutdown() {
	fmt.Println("Shutting down server carefully...")
	rs.finishRequested = true
	rs.activeConns.Wait()
}
