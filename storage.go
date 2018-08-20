package prekeyserver

import "github.com/coyim/gotrax"

type storage interface {
	storeClientProfile(string, *gotrax.ClientProfile) error
	storePrekeyProfile(string, *prekeyProfile) error
	storePrekeyMessages(string, []*prekeyMessage) error
	numberStored(string, uint32) uint32
	retrieveFor(string) []*prekeyEnsemble
	cleanup()
}
