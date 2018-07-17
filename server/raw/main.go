package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	pks "github.com/otrv4/otrng-prekey-server"
)

var signalHandler = make(chan os.Signal, 1)

func main() {
	flag.Parse()
	rs := &rawServer{}
	ending := make(chan bool)

	if e := rs.load(pks.CreateFactory(rand.Reader)); e != nil {
		fmt.Println(e)
		return
	}

	go func() {
		signal.Notify(signalHandler, os.Interrupt, syscall.SIGTERM)
		select {
		case <-signalHandler:
			rs.shutdown()
		case <-ending:
		}
	}()

	if e := rs.run(); e != nil {
		fmt.Println(e)
		ending <- true
		return
	}
}
