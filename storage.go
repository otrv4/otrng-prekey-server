package prekeyserver

import "github.com/otrv4/gotrx"

type storage interface {
	storeClientProfile(string, *gotrx.ClientProfile) error
	storePrekeyProfile(string, *prekeyProfile) error
	storePrekeyMessages(string, []*prekeyMessage) error
	numberStored(string, uint32) uint32
	retrieveFor(string) []*prekeyEnsemble
	cleanup()
}
