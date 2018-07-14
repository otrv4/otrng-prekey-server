package prekeyserver

import (
	"crypto/rand"
	"io"
	"time"
)

type Factory interface {
	CreateKeypair() Keypair
	LoadKeypairFrom(r io.Reader) Keypair
	LoadStorageType(name string) Storage
	NewServer(identity string, keys Keypair, fragLen int, st Storage, sessionTimeout, fragmentTimeout time.Duration) Server
}

type Keypair interface {
	StoreInto(io.Writer)
	Fingerprint() []byte
	realKeys() *keypair
}

type Storage interface {
	createStorage() storage
}

type Server interface {
	Handle(from, message string) ([]string, error)
}

func CreateFactory(rand io.Reader) Factory {
	return &realFactory{rand}
}

type realFactory struct {
	r io.Reader
}

func (f *realFactory) randReader() io.Reader {
	if f.r == nil {
		return rand.Reader
	}
	return f.r
}

type inMemoryStorageFactory struct{}

func (*inMemoryStorageFactory) createStorage() storage {
	return createInMemoryStorage()
}

func (*realFactory) LoadStorageType(name string) Storage {
	if name == "in-memory" {
		return &inMemoryStorageFactory{}
	}

	// TODO: return something better
	return nil
}

func (*realFactory) LoadKeypairFrom(r io.Reader) Keypair {
	// TODO: implement fully
	return nil
}

func (f *realFactory) CreateKeypair() Keypair {
	return generateKeypair(f)
}

func (*realFactory) NewServer(identity string, keys Keypair, fragLen int, st Storage, sessionTimeout, fragmentTimeout time.Duration) Server {
	kp := keys.realKeys()
	gs := &GenericServer{
		identity:             identity,
		fingerprint:          kp.fingerprint(),
		key:                  kp,
		fragLen:              fragLen,
		fragmentations:       newFragmentations(),
		sessions:             newSessionManager(),
		storageImpl:          st.createStorage(),
		sessionTimeout:       sessionTimeout,
		fragmentationTimeout: fragmentTimeout,
	}
	gs.messageHandler = &otrngMessageHandler{s: gs}
	return gs
}
