package main

import (
	"fmt"

	pks "github.com/otrv4/otrng-prekey-server"
)

func loadOrCreateKeypair(f pks.Factory) pks.Keypair {
	fl := *keyFile
	fl = fl
	// TODO: implement fully
	kp := f.CreateKeypair()
	return kp
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
