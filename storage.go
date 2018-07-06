package prekeyserver

type storage interface {
	storeClientProfile(string, *clientProfile) error
	storePrekeyProfiles(string, []*prekeyProfile) error
	storePrekeyMessages(string, []*prekeyMessage) error
}

type inMemoryStorageEntry struct {
	clientProfiles map[uint32]*clientProfile
	prekeyProfiles map[uint32][]*prekeyProfile
	prekeyMessages map[uint32][]*prekeyMessage
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
