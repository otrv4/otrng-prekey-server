package prekeyserver

import (
	"bytes"
	"crypto/dsa"
	"errors"
	"time"

	"github.com/coyim/gotrax"
	"github.com/otrv4/ed448"
)

type clientProfile struct {
	instanceTag           uint32
	publicKey             *publicKey
	versions              []byte
	expiration            time.Time
	dsaKey                *dsa.PublicKey
	transitionalSignature []byte
	sig                   *eddsaSignature
}

type prekeyProfile struct {
	instanceTag  uint32
	expiration   time.Time
	sharedPrekey *publicKey
	sig          *eddsaSignature
}

type prekeyMessage struct {
	identifier  uint32
	instanceTag uint32
	y           ed448.Point
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

	if !bytes.Contains(m.versions, []byte{'4'}) {
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

func generatePrekeyProfile(wr gotrax.WithRandom, tag uint32, expiration time.Time, longTerm *keypair) (*prekeyProfile, *keypair) {
	sharedKey := generateKeypair(wr)
	sharedKey.pub.keyType = sharedPrekeyKey
	pp := &prekeyProfile{
		instanceTag:  tag,
		expiration:   expiration,
		sharedPrekey: sharedKey.pub,
	}

	pp.sig = &eddsaSignature{s: pp.generateSignature(longTerm)}

	return pp, sharedKey
}

func generatePrekeyMessage(wr gotrax.WithRandom, tag uint32) (*prekeyMessage, *keypair) {
	ident := gotrax.RandomUint32(wr)
	y := generateKeypair(wr)
	b := []byte{0x04}

	return &prekeyMessage{
		identifier:  ident,
		instanceTag: tag,
		y:           y.pub.k,
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

func (m *clientProfile) generateSignature(kp *keypair) [114]byte {
	msg := m.serializeForSignature()
	return ed448.DSASign(kp.sym, kp.pub.k, msg)
}

func (pp *prekeyProfile) validate(tag uint32, pub *publicKey) error {
	if pp.instanceTag != tag {
		return errors.New("invalid instance tag in prekey profile")
	}

	if !ed448.DSAVerify(pp.sig.s, pub.k, pp.serializeForSignature()) {
		return errors.New("invalid signature in prekey profile")
	}

	if pp.expiration.Before(time.Now()) {
		return errors.New("prekey profile has expired")
	}

	if validatePoint(pp.sharedPrekey.k) != nil {
		return errors.New("prekey profile shared prekey is not a valid point")
	}

	return nil
}

func (pm *prekeyMessage) validate(tag uint32) error {
	if pm.instanceTag != tag {
		return errors.New("invalid instance tag in prekey message")
	}

	if validatePoint(pm.y) != nil {
		return errors.New("prekey profile Y point is not a valid point")
	}

	if validateDHValue(pm.b) != nil {
		return errors.New("prekey profile B value is not a valid DH group member")
	}

	return nil
}

func (m *clientProfile) hasExpired() bool {
	return m.expiration.Before(time.Now())
}

func (pp *prekeyProfile) hasExpired() bool {
	return pp.expiration.Before(time.Now())
}
