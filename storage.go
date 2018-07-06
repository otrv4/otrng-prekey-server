package prekeyserver

type storage interface {
	storeClientProfile(string, *clientProfile) error
	storePrekeyProfiles(string, []*prekeyProfile) error
	storePrekeyMessages(string, []*prekeyMessage) error
	numberStored(string, uint32) uint32
	retrieveFor(string) []*prekeyEnsemble
}

type inMemoryStorageEntry struct {
	clientProfiles map[uint32]*clientProfile
	prekeyProfiles map[uint32][]*prekeyProfile
	prekeyMessages map[uint32][]*prekeyMessage
}

func (s *inMemoryStorageEntry) retrieve() []*prekeyEnsemble {
	entries := []*prekeyEnsemble{}
	for itag, cp := range s.clientProfiles {
		pp, ok := s.prekeyProfiles[itag]
		pms, ok2 := s.prekeyMessages[itag]
		if ok && ok2 && len(pp) > 0 && len(pms) > 0 {
			entries = append(entries, &prekeyEnsemble{
				cp: cp,
				pp: pp[0],
				pm: pms[0],
			})
			s.prekeyMessages[itag] = pms[1:]
		}
	}
	return entries
}

type inMemoryStorage struct {
	perUser map[string]*inMemoryStorageEntry
}

func createInMemoryStorage() *inMemoryStorage {
	return &inMemoryStorage{
		perUser: make(map[string]*inMemoryStorageEntry),
	}
}

func (s *inMemoryStorage) storageEntryFor(from string) *inMemoryStorageEntry {
	se, ok := s.perUser[from]
	if !ok {
		se = &inMemoryStorageEntry{
			clientProfiles: make(map[uint32]*clientProfile),
			prekeyProfiles: make(map[uint32][]*prekeyProfile),
			prekeyMessages: make(map[uint32][]*prekeyMessage),
		}
		s.perUser[from] = se
	}
	return se
}

func (s *inMemoryStorage) storeClientProfile(from string, cp *clientProfile) error {
	se := s.storageEntryFor(from)
	se.clientProfiles[cp.instanceTag] = cp
	return nil
}

func (s *inMemoryStorage) storePrekeyProfiles(from string, pps []*prekeyProfile) error {
	se := s.storageEntryFor(from)
	spps := se.prekeyProfiles[pps[0].instanceTag]
	for _, pp := range pps {
		spps = append(spps, pp)
	}
	se.prekeyProfiles[pps[0].instanceTag] = spps
	return nil
}

func (s *inMemoryStorage) storePrekeyMessages(from string, pms []*prekeyMessage) error {
	se := s.storageEntryFor(from)
	spms := se.prekeyMessages[pms[0].instanceTag]
	for _, pm := range pms {
		spms = append(spms, pm)
	}
	se.prekeyMessages[pms[0].instanceTag] = spms
	return nil
}

func (s *inMemoryStorage) numberStored(from string, tag uint32) uint32 {
	pu, ok := s.perUser[from]
	if !ok {
		return 0
	}
	return uint32(len(pu.prekeyMessages[tag]))
}

func (s *inMemoryStorage) retrieveFor(from string) []*prekeyEnsemble {
	pu, ok := s.perUser[from]
	if !ok {
		return nil
	}
	return pu.retrieve()
}
