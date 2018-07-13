package prekeyserver

import (
	"sync"
	"time"

	"github.com/otrv4/ed448"
)

type sessionManager struct {
	s map[string]*realSession
	sync.RWMutex
}

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
	sync.Mutex
}

// expects the lock to be held
func (s *realSession) touch() {
	s.lastTouched = time.Now()
}

func (s *realSession) save(kp *keypair, i ed448.Point, tag uint32, cp *clientProfile) {
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

func (s *realSession) clientProfile() *clientProfile {
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

func (s *realSession) keypairS() *keypair {
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
	return kdfx(usagePreMACKey, 64, kdfx(usageSK, skLength, serializePoint(ed448.PointScalarMul(s.i, s.s.priv.k))))
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
