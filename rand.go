package prekeyserver

import (
	"crypto/rand"
	"io"
)

func (g *GenericServer) RandReader() io.Reader {
	if g.rand != nil {
		return g.rand
	}
	return rand.Reader
}
