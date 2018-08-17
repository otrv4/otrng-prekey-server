package prekeyserver

import (
	"crypto/rand"
	"io"

	"github.com/coyim/gotrax"
)

// WithRandom exposes randomness of a type
type WithRandom interface {
	randReader() io.Reader
}

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

type realRandom struct{}

func defaultRandom() *realRandom {
	return &realRandom{}
}

func (*realRandom) randReader() io.Reader {
	return rand.Reader
}

func randomUint32(w WithRandom) uint32 {
	b := [4]byte{}
	randomInto(w, b[:])
	_, ww, _ := gotrax.ExtractWord(b[:])
	return ww
}
