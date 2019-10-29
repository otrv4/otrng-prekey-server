package prekeyserver

import (
	"sync"
	"time"

	"github.com/otrv4/ed448"
	"github.com/otrv4/gotrx"
)

type sessionManager struct {
	s map[string]*realSession
	sync.RWMutex
}

type session interface {
	save(*gotrx.Keypair, ed448.Point, uint32, *gotrx.ClientProfile)
	instanceTag() uint32
	macKey() []byte
	sharedSecret() []byte
	clientProfile() *gotrx.ClientProfile
	pointI() ed448.Point
	keypairS() *gotrx.Keypair
	hasExpired(time.Duration) bool
}

type realSession struct {
	tag         uint32
	s           *gotrx.Keypair
	i           ed448.Point
	cp          *gotrx.ClientProfile
	storedMac   []byte
	sk          []byte
	lastTouched time.Time
	sync.Mutex
}

// expects the lock to be held
func (s *realSession) touch() {
	s.lastTouched = time.Now()
}

func (s *realSession) save(kp *gotrx.Keypair, i ed448.Point, tag uint32, cp *gotrx.ClientProfile) {
	s.Lock()
	defer s.Unlock()

	s.touch()
	s.s = kp
	s.i = i
	s.tag = tag
	s.cp = cp
}

func (s *realSession) instanceTag() uint32 {
	s.Lock()
	defer s.Unlock()

	s.touch()
	return s.tag
}

func (s *realSession) clientProfile() *gotrx.ClientProfile {
	s.Lock()
	defer s.Unlock()

	s.touch()
	return s.cp
}

func (s *realSession) pointI() ed448.Point {
	s.Lock()
	defer s.Unlock()

	s.touch()
	return s.i
}

func (s *realSession) keypairS() *gotrx.Keypair {
	s.Lock()
	defer s.Unlock()

	s.touch()
	return s.s
}

func (s *realSession) macKey() []byte {
	s.Lock()
	defer s.Unlock()

	s.touch()
	if s.storedMac != nil {
		return s.storedMac
	}
	return gotrx.KdfPrekeyServer(usagePreMACKey, 64, gotrx.KdfPrekeyServer(usageSK, skLength, gotrx.SerializePoint(ed448.PointScalarMul(s.i, s.s.Priv.K()))))
}

func (s *realSession) sharedSecret() []byte {
	s.Lock()
	defer s.Unlock()

	s.touch()
	if s.sk != nil {
		return s.sk
	}
	return gotrx.KdfPrekeyServer(usageSK, skLength, gotrx.SerializePoint(ed448.PointScalarMul(s.i, s.s.Priv.K())))
}

func (s *realSession) hasExpired(timeout time.Duration) bool {
	s.Lock()
	defer s.Unlock()

	return s.lastTouched.Add(timeout).Before(time.Now())
}

func newSessionManager() *sessionManager {
	return &sessionManager{
		s: make(map[string]*realSession),
	}
}

func (sm *sessionManager) get(name string) session {
	sm.RLock()
	s, ok := sm.s[name]
	sm.RUnlock()
	if !ok {
		s = &realSession{}
		sm.Lock()
		sm.s[name] = s
		sm.Unlock()
	}
	return s
}

func (sm *sessionManager) complete(name string) {
	sm.Lock()
	defer sm.Unlock()

	delete(sm.s, name)
}

func (sm *sessionManager) has(name string) bool {
	sm.RLock()
	defer sm.RUnlock()

	_, ok := sm.s[name]
	return ok
}

func (sm *sessionManager) cleanup(timeout time.Duration) {
	sm.Lock()
	defer sm.Unlock()

	toRemove := []string{}
	for nm, s := range sm.s {
		if s.hasExpired(timeout) {
			toRemove = append(toRemove, nm)
		}
	}
	for _, nm := range toRemove {
		delete(sm.s, nm)
	}
}
