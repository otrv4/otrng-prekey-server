package prekeyserver

type storage interface {
	storeClientProfile(string, *clientProfile) error
	storePrekeyProfile(string, *prekeyProfile) error
	storePrekeyMessages(string, []*prekeyMessage) error
	numberStored(string, uint32) uint32
	retrieveFor(string) []*prekeyEnsemble
	cleanup()
}
