package prekeyserver

import "github.com/twstrike/ed448"

type ringSignature struct {
	c1 ed448.Scalar
	r1 ed448.Scalar
	c2 ed448.Scalar
	r2 ed448.Scalar
	c3 ed448.Scalar
	r3 ed448.Scalar
}

func generateSignature(a1 *privateKey, A1, A2, A3 *publicKey, m []byte) (*ringSignature, error) {

	// A1, A2, and A3 should be checked to verify that they are on the curve Ed448. See Verifying that a point is on the curve section for details.
	// Pick random values t1, c2, c3, r2, r3 in q.
	// Compute T1 = G * t1.
	// Compute T2 = G * r2 + A2 * c2.
	// Compute T3 = G * r3 + A3 * c3.
	// Compute c = HashToScalar(0x1D || G || q || A1 || A2 || A3 || T1 || T2 || T3 || m).
	// Compute c1 = c - c2 - c3 (mod q).
	// Compute r1 = t1 - c1 * a1 (mod q).
	// Send sigma = (c1, r1, c2, r2, c3, r3).

	// TODO: implement
	return nil, nil
}

// verify will actually do the cryptographic validation of the ring signature
func (r *ringSignature) verify() bool {
	// TODO: implement
	return false
}

func (r *ringSignature) deserialize(buf []byte) ([]byte, bool) {
	buf, r.c1, _ = deserializeScalar(buf)
	buf, r.r1, _ = deserializeScalar(buf)
	buf, r.c2, _ = deserializeScalar(buf)
	buf, r.r2, _ = deserializeScalar(buf)
	buf, r.c3, _ = deserializeScalar(buf)
	buf, r.r3, _ = deserializeScalar(buf)
	return buf, true
}

func (r *ringSignature) serialize() []byte {
	var out []byte
	out = append(out, serializeScalar(r.c1)...)
	out = append(out, serializeScalar(r.r1)...)
	out = append(out, serializeScalar(r.c2)...)
	out = append(out, serializeScalar(r.r2)...)
	out = append(out, serializeScalar(r.c3)...)
	out = append(out, serializeScalar(r.r3)...)
	return out
}

func serializeScalar(s ed448.Scalar) []byte {
	return s.Encode()
}

func deserializeScalar(buf []byte) ([]byte, ed448.Scalar, bool) {
	ts := ed448.NewScalar([]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})
	ts.Decode(buf[0:56])
	return buf[56:], ts, true

}
