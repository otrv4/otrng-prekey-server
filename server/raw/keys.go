package main

import (
	"fmt"
	"os"

	"github.com/otrv4/gotrx"
	pks "github.com/otrv4/otrng-prekey-server"
)

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func loadOrCreateKeypair(f pks.Factory) (pks.Keypair, error) {
	fl := *keyFile
	if fileExists(fl) {
		file, e := os.Open(fl)
		if e != nil {
			return nil, e
		}
		defer file.Close()
		return f.LoadKeypairFrom(file)
	}

	file, e := os.Create(fl)
	if e != nil {
		return nil, e
	}

	defer file.Close()
	ret := f.CreateKeypair()

	if e := f.StoreKeysInto(ret, file); e != nil {
		return nil, e
	}

	return ret, nil
}

func formatFingerprint(fp gotrx.Fingerprint) string {
	result := ""
	sep := ""

	for ix := 0; ix < 7; ix++ {
		result = fmt.Sprintf("%s%s%02X%02X%02X%02X%02X%02X%02X%02X", result, sep, fp[ix*8+0], fp[ix*8+1], fp[ix*8+2], fp[ix*8+3], fp[ix*8+4], fp[ix*8+5], fp[ix*8+6], fp[ix*8+7])
		sep = " "
	}

	return result
}
