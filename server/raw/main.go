package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	pks "github.com/otrv4/otrng-prekey-server"
)

func main() {
	flag.Parse()
	f := pks.CreateFactory(rand.Reader)
	kp, _ := loadOrCreateKeypair(f)
	storage, _ := f.LoadStorageType(*storageEngine)
	server := f.NewServer(*serverIdentity,
		kp,
		int(*fragLen),
		storage,
		time.Duration(*sessionTimeout)*time.Minute,
		time.Duration(*fragmentationTimeout)*time.Minute)

	fmt.Printf("Starting server on %s:%v...\n", *listenIP, *listenPort)
	fmt.Printf("  [%s]\n", formatFingerprint(kp.Fingerprint()))

	listenWith(server)
}

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
		// print e
		return
	}
	res, e := protocolHandleData(data, s)
	if e != nil {
		// print e
		return
	}
	_, e = c.Write(res)
	if e != nil {
		// print e
		return
	}
}
