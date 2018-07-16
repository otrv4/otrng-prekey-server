package main

import (
	"bytes"
	"io"
	"os"
)

type stdoutCapture struct {
	old  *os.File
	outC chan string
	r, w *os.File
}

func startStdoutCapture() *stdoutCapture {
	s := &stdoutCapture{}

	s.old = os.Stdout
	s.r, s.w, _ = os.Pipe()
	os.Stdout = s.w
	s.outC = make(chan string)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, s.r)
		s.outC <- buf.String()
	}()

	return s
}

func (s *stdoutCapture) finish() string {
	s.w.Close()
	return <-s.outC
}

func (s *stdoutCapture) restore() {
	s.w.Close()
	os.Stdout = s.old
}
