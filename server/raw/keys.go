package main

import (
	"fmt"
	"os"

	pks "github.com/otrv4/otrng-prekey-server"
)

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func loadOrCreateKeypair(f pks.Factory) (pks.Keypair, error) {
	fl := *keyFile
	if fileExists(fl) {
		file, err := os.Open(fl)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		fmt.Printf("... loading keypair from '%v'\n", fl)
		return f.LoadKeypairFrom(file)
	}
	file, err := os.Create(fl)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	fmt.Printf("... creating keypair and storing in '%v'\n", fl)
	ret := f.CreateKeypair()
	if e := ret.StoreInto(file); e != nil {
		return nil, e
	}

	return ret, nil
}

func formatFingerprint(fp []byte) string {
	result := ""
	sep := ""

	for ix := 0; ix < 7; ix++ {
		result = fmt.Sprintf("%s%s%02X%02X%02X%02X%02X%02X%02X%02X", result, sep, fp[ix*8+0], fp[ix*8+1], fp[ix*8+2], fp[ix*8+3], fp[ix*8+4], fp[ix*8+5], fp[ix*8+6], fp[ix*8+7])
		sep = " "
	}

	return result
}
