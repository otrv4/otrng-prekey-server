package gotrax

// Deserialize will deserialize a ring signature or return failure
func (r *RingSignature) Deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	if buf, r.C1, ok = DeserializeScalar(buf); !ok {
		return nil, false
	}

	if buf, r.R1, ok = DeserializeScalar(buf); !ok {
		return nil, false
	}

	if buf, r.C2, ok = DeserializeScalar(buf); !ok {
		return nil, false
	}

	if buf, r.R2, ok = DeserializeScalar(buf); !ok {
		return nil, false
	}

	if buf, r.C3, ok = DeserializeScalar(buf); !ok {
		return nil, false
	}

	if buf, r.R3, ok = DeserializeScalar(buf); !ok {
		return nil, false
	}

	return buf, true
}

// Serialize will return the serialization of the ring signature
func (r *RingSignature) Serialize() []byte {
	var out []byte
	out = append(out, SerializeScalar(r.C1)...)
	out = append(out, SerializeScalar(r.R1)...)
	out = append(out, SerializeScalar(r.C2)...)
	out = append(out, SerializeScalar(r.R2)...)
	out = append(out, SerializeScalar(r.C3)...)
	out = append(out, SerializeScalar(r.R3)...)
	return out
}
