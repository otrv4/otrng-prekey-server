package main

import (
	"fmt"
	"io"
	"net"
	"time"

	pks "github.com/otrv4/otrng-prekey-server"
)

type rawServer struct {
	s  pks.Server
	l  net.Listener
	kp pks.Keypair
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
	fmt.Printf("Starting server on %s:%v...\n", *listenIP, *listenPort)
	fmt.Printf("  [%s]\n", formatFingerprint(rs.kp.Fingerprint()))

	if e := rs.listenWith(); e != nil {
		return fmt.Errorf("encountered error when running listener: %v", e)
	}
	return nil
}

func (rs *rawServer) listenWith() error {
	l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", *listenIP, *listenPort))
	if err != nil {
		return err
	}
	rs.l = l
	defer rs.l.Close()
	for {
		conn, err := rs.l.Accept()
		if err != nil {
			return err
		}
		go rs.handleRequest(conn)
	}
}

func readAvailable(r io.Reader) ([]byte, error) {
	res := make([]byte, 0, 2048)
	buf := make([]byte, 1024)
	done := false

	for !done {
		n, e := r.Read(buf)
		if e != nil && e != io.EOF {
			return nil, e
		}
		res = append(res, buf[0:n]...)
		done = e == io.EOF || n < len(buf)
	}

	return res, nil
}

func (rs *rawServer) handleRequest(c net.Conn) {
	defer c.Close()
	data, e := readAvailable(c)
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
