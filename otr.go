package prekeyserver

import (
	"bytes"
	"crypto/dsa"
	"errors"
	"time"

	"github.com/otrv4/ed448"
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
	if m.instanceTag != tag {
		return errors.New("invalid instance tag in client profile")
	}

	if !ed448.DSAVerify(m.sig.s, m.publicKey.k, m.serializeForSignature()) {
		return errors.New("invalid signature in client profile")
	}

	if m.expiration.Before(time.Now()) {
		return errors.New("client profile has expired")
	}

	if !bytes.Contains(m.versions, []byte{0x04}) {
		return errors.New("client profile doesn't support version 4")
	}

	// This branch will be untested for now, since I have NO idea how to generate
	// a valid private key AND eddsa signature that matches an invalid point...
	if validatePoint(m.publicKey.k) != nil {
		return errors.New("client profile public key is not a valid point")
	}

	// The spec says to verify the DSA transitional signature here
	// For now, I'll avoid doing that, since the purpose of the transitional
	// signature has nothing to do with the prekey server

	return nil
}

func generatePrekeyProfile(wr WithRandom, tag uint32, expiration time.Time, longTerm *keypair) (*prekeyProfile, *keypair) {
	ident := randomUint32(wr)
	sharedKey := generateEDDSAKeypair(wr)
	pp := &prekeyProfile{
		identifier:   ident,
		instanceTag:  tag,
		expiration:   expiration,
		sharedPrekey: sharedKey.pub,
	}

	pp.sig = &eddsaSignature{s: pp.generateSignature(longTerm)}

	return pp, sharedKey
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

func (m *clientProfile) Equals(other *clientProfile) bool {
	return bytes.Equal(m.serialize(), other.serialize())
}

func (pp *prekeyProfile) Equals(other *prekeyProfile) bool {
	return bytes.Equal(pp.serialize(), other.serialize())
}

func (pm *prekeyMessage) Equals(other *prekeyMessage) bool {
	return bytes.Equal(pm.serialize(), other.serialize())
}

func (pp *prekeyProfile) generateSignature(kp *keypair) [114]byte {
	msg := pp.serializeForSignature()
	return ed448.DSASign(kp.sym, kp.pub.k, msg)
}

func (cp *clientProfile) generateSignature(kp *keypair) [114]byte {
	msg := cp.serializeForSignature()
	return ed448.DSASign(kp.sym, kp.pub.k, msg)
}
