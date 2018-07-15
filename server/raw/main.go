package main

import (
	"crypto/rand"
	"flag"
	"fmt"

	pks "github.com/otrv4/otrng-prekey-server"
)

func main() {
	flag.Parse()
	rs := &rawServer{}

	if e := rs.load(pks.CreateFactory(rand.Reader)); e != nil {
		fmt.Println(e)
		return
	}

	if e := rs.run(); e != nil {
		fmt.Println(e)
		return
	}
}
