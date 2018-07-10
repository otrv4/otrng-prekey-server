package prekeyserver

import "github.com/otrv4/ed448"

type session interface {
	save(*keypair, ed448.Point, uint32)
	instanceTag() uint32
	macKey() []byte
}

type realSession struct {
	tag       uint32
	s         *keypair
	i         ed448.Point
	storedMac []byte
}

func (s *realSession) save(kp *keypair, i ed448.Point, tag uint32) {
	s.s = kp
	s.i = i
	s.tag = tag
}

func (s *realSession) instanceTag() uint32 {
	return s.tag
}

func (s *realSession) macKey() []byte {
	if s.storedMac != nil {
		return s.storedMac
	}
	return kdfx(usagePreMACKey, 64, kdfx(usageSK, skLength, serializePoint(ed448.PointScalarMul(s.i, s.s.priv.k))))
}
