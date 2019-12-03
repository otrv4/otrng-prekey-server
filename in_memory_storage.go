package prekeyserver

import (
	"sync"

	"github.com/otrv4/gotrx"
)

func isInMemoryStorageDescriptor(desc string) bool {
	return desc == "in-memory"
}

type inMemoryStorageFactory struct{}

func (*inMemoryStorageFactory) createStorage() storage {
	return createInMemoryStorage()
}

type inMemoryStorageEntry struct {
	clientProfiles map[uint32]*gotrx.ClientProfile
	prekeyProfiles map[uint32]*prekeyProfile
	prekeyMessages map[uint32][]*prekeyMessage
	sync.Mutex
}

type inMemoryStorage struct {
	perUser map[string]*inMemoryStorageEntry
	sync.RWMutex
}

func (s *inMemoryStorageEntry) retrieve() []*prekeyEnsemble {
	s.Lock()
	defer s.Unlock()

	entries := []*prekeyEnsemble{}
	for itag, cp := range s.clientProfiles {
		pp, ok := s.prekeyProfiles[itag]
		pms, ok2 := s.prekeyMessages[itag]
		if ok && ok2 && pp != nil && len(pms) > 0 {
			entries = append(entries, &prekeyEnsemble{
				cp: cp,
				pp: pp,
				pm: pms[0],
			})
			s.prekeyMessages[itag] = pms[1:]
		}
	}
	return entries
}

func createInMemoryStorage() *inMemoryStorage {
	return &inMemoryStorage{
		perUser: make(map[string]*inMemoryStorageEntry),
	}
}

func (s *inMemoryStorage) storageEntryFor(from string) *inMemoryStorageEntry {
	s.RLock()
	se, ok := s.perUser[from]
	s.RUnlock()
	if !ok {
		se = &inMemoryStorageEntry{
			clientProfiles: make(map[uint32]*gotrx.ClientProfile),
			prekeyProfiles: make(map[uint32]*prekeyProfile),
			prekeyMessages: make(map[uint32][]*prekeyMessage),
		}
		s.Lock()
		defer s.Unlock()
		s.perUser[from] = se
	}
	return se
}

func (s *inMemoryStorage) storeClientProfile(from string, cp *gotrx.ClientProfile) error {
	if cp != nil {
		se := s.storageEntryFor(from)
		se.Lock()
		defer se.Unlock()
		se.clientProfiles[cp.InstanceTag] = cp
	}
	return nil
}

func (s *inMemoryStorage) storePrekeyProfile(from string, pp *prekeyProfile) error {
	if pp != nil {
		se := s.storageEntryFor(from)
		se.Lock()
		defer se.Unlock()
		se.prekeyProfiles[pp.instanceTag] = pp
	}
	return nil
}

func (s *inMemoryStorage) storePrekeyMessages(from string, pms []*prekeyMessage) error {
	if len(pms) == 0 {
		return nil
	}
	se := s.storageEntryFor(from)
	se.Lock()
	defer se.Unlock()
	spms := se.prekeyMessages[pms[0].instanceTag]
	spms = append(spms, pms...)

	se.prekeyMessages[pms[0].instanceTag] = spms
	return nil
}

func (s *inMemoryStorage) numberStored(from string, tag uint32) uint32 {
	s.RLock()
	defer s.RUnlock()
	pu, ok := s.perUser[from]
	if !ok {
		return 0
	}
	return uint32(len(pu.prekeyMessages[tag]))
}

func (s *inMemoryStorage) retrieveFor(from string) []*prekeyEnsemble {
	s.RLock()
	pu, ok := s.perUser[from]
	s.RUnlock()
	if !ok {
		return nil
	}
	return pu.retrieve()
}

func (s *inMemoryStorageEntry) cleanupClientProfiles() {
	toRemove := []uint32{}
	for itag, cp := range s.clientProfiles {
		if cp.HasExpired() {
			toRemove = append(toRemove, itag)
		}
	}
	for _, itag := range toRemove {
		delete(s.clientProfiles, itag)
	}
}

func (s *inMemoryStorageEntry) cleanupPrekeyProfiles() {
	toRemove := []uint32{}
	for itag, pp := range s.prekeyProfiles {
		if pp.hasExpired() {
			toRemove = append(toRemove, itag)
		}
	}
	for _, itag := range toRemove {
		delete(s.prekeyProfiles, itag)
	}
}

func (s *inMemoryStorageEntry) hasAnyEntries() bool {
	return len(s.clientProfiles) != 0 ||
		len(s.prekeyProfiles) != 0 ||
		len(s.prekeyMessages) != 0
}

func (s *inMemoryStorageEntry) cleanup() bool {
	s.Lock()
	defer s.Unlock()
	s.cleanupClientProfiles()
	s.cleanupPrekeyProfiles()

	return s.hasAnyEntries()
}

func (s *inMemoryStorage) cleanup() {
	s.Lock()
	defer s.Unlock()
	toRemove := []string{}
	for pu, pus := range s.perUser {
		if !pus.cleanup() {
			toRemove = append(toRemove, pu)
		}
	}
	for _, pu := range toRemove {
		delete(s.perUser, pu)
	}
}
