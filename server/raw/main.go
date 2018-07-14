package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"time"

	pks "github.com/otrv4/otrng-prekey-server"
)

func main() {
	flag.Parse()
	f := pks.CreateFactory(rand.Reader)
	kp := loadOrCreateKeypair(f)
	storage := f.LoadStorageType(*storageEngine)
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

func listenWith(s pks.Server) {
	// TODO: implement TCP listener here
}
