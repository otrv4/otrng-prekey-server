package prekeyserver

import "github.com/coyim/gotrax"

func (p *ecdhProof) serialize() []byte {
	out := append([]byte{}, p.c...)
	out = append(out, gotrax.SerializeScalar(p.v)...)
	return out
}

func (p *ecdhProof) deserialize(buf []byte) ([]byte, bool) {
	var ok bool

	if buf, p.c, ok = gotrax.ExtractFixedData(buf, 64); !ok {
		return nil, false
	}

	if buf, p.v, ok = gotrax.DeserializeScalar(buf); !ok {
		return nil, false
	}

	return buf, true
}

func (p *dhProof) serialize() []byte {
	out := append([]byte{}, p.c...)
	out = gotrax.AppendMPI(out, p.v)
	return out
}

func (p *dhProof) deserialize(buf []byte) ([]byte, bool) {
	var ok bool

	if buf, p.c, ok = gotrax.ExtractFixedData(buf, 64); !ok {
		return nil, false
	}

	if buf, p.v, ok = gotrax.ExtractMPI(buf); !ok {
		return nil, false
	}

	return buf, true
}
