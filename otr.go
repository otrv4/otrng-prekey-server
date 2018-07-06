package prekeyserver

import (
	"bytes"
	"crypto/dsa"
	"errors"
	"time"
)

type clientProfile struct {
	identifier            uint32
	instanceTag           uint32
	publicKey             *publicKey
	versions              []byte
	expiration            time.Time
	dsaKey                *dsa.PublicKey
	transitionalSignature []byte
	sig                   *eddsaSignature
}

type prekeyProfile struct {
	identifier   uint32
	instanceTag  uint32
	expiration   time.Time
	sharedPrekey *publicKey
	sig          *eddsaSignature
}

type prekeyMessage struct {
	identifier  uint32
	instanceTag uint32
	y           *publicKey
	b           []byte
}

type prekeyEnsemble struct {
	cp *clientProfile
	pp *prekeyProfile
	pm *prekeyMessage
}

func (m *clientProfile) validate(tag uint32) error {
	// TODO: finish this
	if m.instanceTag != tag {
		return errors.New("invalid instance tag in client profile")
	}
	return nil
}

func generatePrekeyProfile(wr WithRandom, tag uint32, expiration time.Time, longTerm *keypair) (*prekeyProfile, *keypair) {
	ident := randomUint32(wr)
	sharedKey := generateEDDSAKeypair(wr)
	// TODO:
	// This eddsa signature is NOT correct, since we have no way of generating proper eddsa signatures at the moment.
	// This will all have to wait
	sig := &eddsaSignature{s: [114]byte{0x03, 0x02, 0x01}}

	return &prekeyProfile{
		identifier:   ident,
		instanceTag:  tag,
		expiration:   expiration,
		sharedPrekey: sharedKey.pub,
		sig:          sig,
	}, sharedKey
}

func generatePrekeyMessage(wr WithRandom, tag uint32) (*prekeyMessage, *keypair) {
	ident := randomUint32(wr)
	y := generateECDHKeypair(wr)
	b := randomBytes(wr, 80)

	return &prekeyMessage{
		identifier:  ident,
		instanceTag: tag,
		y:           y.pub,
		b:           b,
	}, y
}

func (cp *clientProfile) Equals(other *clientProfile) bool {
	return bytes.Equal(cp.serialize(), other.serialize())
}

func (pp *prekeyProfile) Equals(other *prekeyProfile) bool {
	return bytes.Equal(pp.serialize(), other.serialize())
}

func (pm *prekeyMessage) Equals(other *prekeyMessage) bool {
	return bytes.Equal(pm.serialize(), other.serialize())
}
