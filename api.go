package prekeyserver

import (
	"crypto/rand"
	"encoding/json"
	"io"
	"time"
)

type Factory interface {
	CreateKeypair() Keypair
	LoadKeypairFrom(r io.Reader) (Keypair, error)
	LoadStorageType(name string) Storage
	NewServer(identity string, keys Keypair, fragLen int, st Storage, sessionTimeout, fragmentTimeout time.Duration) Server
}

type Keypair interface {
	StoreInto(io.Writer) error
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

type keypairInStorage struct {
	Symmetric string
	Private   string
	Public    string
}

// TODO: errors
func (kis *keypairInStorage) intoKeypair() (*keypair, error) {
	sym, _ := decodeMessage(kis.Symmetric)
	privb, _ := decodeMessage(kis.Private)
	pubb, _ := decodeMessage(kis.Public)
	_, priv, _ := deserializeScalar(privb)
	_, pub, _ := deserializePoint(pubb)
	res := &keypair{}
	copy(res.sym[:], sym)
	res.pub = &publicKey{k: pub}
	res.priv = &privateKey{k: priv}
	return res, nil
}

// TODO: errors
func (*realFactory) LoadKeypairFrom(r io.Reader) (Keypair, error) {
	dec := json.NewDecoder(r)
	res := &keypairInStorage{}
	if e := dec.Decode(res); e != nil {
		return nil, e
	}
	return res.intoKeypair()
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
