package prekeyserver

import (
	"time"

	"github.com/otrv4/ed448"
)

type session interface {
	save(*keypair, ed448.Point, uint32, *clientProfile)
	instanceTag() uint32
	macKey() []byte
	clientProfile() *clientProfile
	pointI() ed448.Point
	keypairS() *keypair
	hasExpired(time.Duration) bool
}

type realSession struct {
	tag         uint32
	s           *keypair
	i           ed448.Point
	cp          *clientProfile
	storedMac   []byte
	lastTouched time.Time
}

func (s *realSession) touch() {
	s.lastTouched = time.Now()
}

func (s *realSession) save(kp *keypair, i ed448.Point, tag uint32, cp *clientProfile) {
	s.touch()
	s.s = kp
	s.i = i
	s.tag = tag
	s.cp = cp
}

func (s *realSession) instanceTag() uint32 {
	s.touch()
	return s.tag
}

func (s *realSession) clientProfile() *clientProfile {
	s.touch()
	return s.cp
}

func (s *realSession) pointI() ed448.Point {
	s.touch()
	return s.i
}

func (s *realSession) keypairS() *keypair {
	s.touch()
	return s.s
}

func (s *realSession) macKey() []byte {
	s.touch()
	if s.storedMac != nil {
		return s.storedMac
	}
	return kdfx(usagePreMACKey, 64, kdfx(usageSK, skLength, serializePoint(ed448.PointScalarMul(s.i, s.s.priv.k))))
}

func (s *realSession) hasExpired(timeout time.Duration) bool {
	return s.lastTouched.Add(timeout).Before(time.Now())
}
