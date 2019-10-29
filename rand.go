package prekeyserver

import (
	"crypto/rand"
	"io"
)

// RandReader implements the gotrx.WithRandom interface
func (g *GenericServer) RandReader() io.Reader {
	if g.rand != nil {
		return g.rand
	}
	return rand.Reader
}
