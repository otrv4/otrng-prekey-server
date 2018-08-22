package prekeyserver

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/coyim/gotrax"
)

// Factory is the main entry point for the otrng prekey server functionality.
type Factory interface {
	CreateKeypair() Keypair
	LoadKeypairFrom(r io.Reader) (Keypair, error)
	LoadStorageType(name string) (Storage, error)
	StoreKeysInto(Keypair, io.Writer) error
	NewServer(identity string, keys Keypair, fragLen int, st Storage, sessionTimeout, fragmentTimeout time.Duration, r Restrictor) Server
}

// Keypair represents the minimum key functionality a server implementation will need
type Keypair interface {
	Fingerprint() gotrax.Fingerprint
}

// Storage has the responsibility of creating new storage implementations
type Storage interface {
	createStorage() storage
}

// Server is the core handling functionality of a prekey server
type Server interface {
	Handle(from, message string) ([]string, error)
}

// CreateFactory will return a new factory that can be used to access
// the basic functionality of the prekey server. The rand argument can
// be a reader to allow for fixed randomness. If nil is given, rand.Reader will
// be used instead.
func CreateFactory(rand io.Reader) Factory {
	return &realFactory{rand}
}

type realFactory struct {
	r io.Reader
}

func (f *realFactory) RandReader() io.Reader {
	if f.r == nil {
		return rand.Reader
	}
	return f.r
}

func (*realFactory) LoadStorageType(name string) (Storage, error) {
	if isInMemoryStorageDescriptor(name) {
		return &inMemoryStorageFactory{}, nil
	} else if isFileStorageDescriptor(name) {
		return createFileStorageFactoryFrom(name)
	}

	return nil, errors.New("unknown storage type")
}

type keypairInStorage struct {
	Symmetric string
	Private   string
	Public    string
}

func (kis *keypairInStorage) intoKeypair() (*gotrax.Keypair, error) {
	sym, ok := decodeMessage(kis.Symmetric)
	if !ok {
		return nil, errors.New("couldn't decode symmetric key")
	}
	privb, ok := decodeMessage(kis.Private)
	if !ok {
		return nil, errors.New("couldn't decode private key")
	}
	pubb, ok := decodeMessage(kis.Public)
	if !ok {
		return nil, errors.New("couldn't decode public key")
	}
	_, priv, ok := gotrax.DeserializeScalar(privb)
	if !ok {
		return nil, errors.New("couldn't decode scalar for private key")
	}
	_, pub, ok := gotrax.DeserializePoint(pubb)
	if !ok {
		return nil, errors.New("couldn't decode point for public key")
	}
	res := &gotrax.Keypair{}
	copy(res.Sym[:], sym)
	res.Pub = gotrax.CreatePublicKey(pub, gotrax.Ed448Key)
	res.Priv = gotrax.CreatePrivateKey(priv)
	return res, nil
}

func (f *realFactory) StoreKeysInto(kpp Keypair, w io.Writer) error {
	kp := kpp.(*gotrax.Keypair)
	enc := json.NewEncoder(w)
	kis := &keypairInStorage{
		Symmetric: encodeMessage(kp.Sym[:]),
		Private:   encodeMessage(gotrax.SerializeScalar(kp.Priv.K())),
		Public:    encodeMessage(gotrax.SerializePoint(kp.Pub.K())),
	}
	return enc.Encode(kis)
}

func (*realFactory) LoadKeypairFrom(r io.Reader) (Keypair, error) {
	dec := json.NewDecoder(r)
	res := &keypairInStorage{}
	if e := dec.Decode(res); e != nil {
		return nil, e
	}
	return res.intoKeypair()
}

func (f *realFactory) CreateKeypair() Keypair {
	return gotrax.GenerateKeypair(f)
}

func (*realFactory) NewServer(identity string, keys Keypair, fragLen int, st Storage, sessionTimeout, fragmentTimeout time.Duration, r Restrictor) Server {
	kp := keys.(*gotrax.Keypair)
	if r == nil {
		r = nullRestrictor
	}
	gs := &GenericServer{
		identity:             identity,
		fingerprint:          kp.Fingerprint(),
		key:                  kp,
		fragLen:              fragLen,
		fragmentations:       newFragmentations(),
		sessions:             newSessionManager(),
		storageImpl:          st.createStorage(),
		sessionTimeout:       sessionTimeout,
		fragmentationTimeout: fragmentTimeout,
		rest:                 r,
	}
	gs.messageHandler = &otrngMessageHandler{s: gs}
	return gs
}
