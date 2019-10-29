package prekeyserver

import "github.com/otrv4/gotrx"

func (p *ecdhProof) serialize() []byte {
	out := append([]byte{}, p.c...)
	out = append(out, gotrx.SerializeScalar(p.v)...)
	return out
}

func (p *ecdhProof) deserialize(buf []byte) ([]byte, bool) {
	var ok bool

	if buf, p.c, ok = gotrx.ExtractFixedData(buf, 64); !ok {
		return nil, false
	}

	if buf, p.v, ok = gotrx.DeserializeScalar(buf); !ok {
		return nil, false
	}

	return buf, true
}

func (p *dhProof) serialize() []byte {
	out := append([]byte{}, p.c...)
	out = gotrx.AppendMPI(out, p.v)
	return out
}

func (p *dhProof) deserialize(buf []byte) ([]byte, bool) {
	var ok bool

	if buf, p.c, ok = gotrx.ExtractFixedData(buf, 64); !ok {
		return nil, false
	}

	if buf, p.v, ok = gotrx.ExtractMPI(buf); !ok {
		return nil, false
	}

	return buf, true
}
