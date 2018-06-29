package prekeyserver

import (
	"crypto/rand"
	"errors"
	"io"
)

type WithRandom interface {
	randReader() io.Reader
}

var errShortRandomRead = errors.New("short read from random source")

func (g *GenericServer) randReader() io.Reader {
	if g.rand != nil {
		return g.rand
	}
	return rand.Reader
}

func randomInto(r WithRandom, b []byte) error {
	if _, err := io.ReadFull(r.randReader(), b); err != nil {
		return errShortRandomRead
	}
	return nil
}
