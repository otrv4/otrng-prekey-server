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
	kp, e := loadOrCreateKeypair(f)
	if e != nil {
		fmt.Printf("Encountered error when loading/creating keypair: %v\n", e)
	}
	storage, e := f.LoadStorageType(*storageEngine)
	if e != nil {
		fmt.Printf("Encountered error when creating storage engine: %v\n", e)
	}
	server := f.NewServer(*serverIdentity,
		kp,
		int(*fragLen),
		storage,
		time.Duration(*sessionTimeout)*time.Minute,
		time.Duration(*fragmentationTimeout)*time.Minute)

	fmt.Printf("Starting server on %s:%v...\n", *listenIP, *listenPort)
	fmt.Printf("  [%s]\n", formatFingerprint(kp.Fingerprint()))

	e = listenWith(server)
	if e != nil {
		fmt.Printf("Encountered error when running listener: %v\n", e)
	}
}
