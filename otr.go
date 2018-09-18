package prekeyserver

import (
	"bytes"
	"crypto/rand"
	"errors"
	"math/big"
	"time"

	"github.com/coyim/gotrax"
	"github.com/otrv4/ed448"
)

type prekeyProfile struct {
	instanceTag  uint32
	expiration   time.Time
	sharedPrekey *gotrax.PublicKey
	sig          *gotrax.EddsaSignature
}

type prekeyMessage struct {
	identifier  uint32
	instanceTag uint32
	y           ed448.Point
	b           *big.Int
}

type prekeyEnsemble struct {
	cp *gotrax.ClientProfile
	pp *prekeyProfile
	pm *prekeyMessage
}

func generatePrekeyProfile(wr gotrax.WithRandom, tag uint32, expiration time.Time, longTerm *gotrax.Keypair) (*prekeyProfile, *gotrax.Keypair) {
	sharedKey := gotrax.GenerateKeypair(wr)
	sharedKey.Pub = gotrax.CreatePublicKey(sharedKey.Pub.K(), gotrax.SharedPrekeyKey)
	pp := &prekeyProfile{
		instanceTag:  tag,
		expiration:   expiration,
		sharedPrekey: sharedKey.Pub,
	}

	pp.sig = gotrax.CreateEddsaSignature(pp.generateSignature(longTerm))

	return pp, sharedKey
}

func generatePrekeyMessage(wr gotrax.WithRandom, tag uint32) (*prekeyMessage, *gotrax.Keypair, *big.Int, *big.Int) {
	ident := gotrax.RandomUint32(wr)
	y := gotrax.GenerateKeypair(wr)
	privB, _ := rand.Int(wr.RandReader(), dhQ)
	pubB := new(big.Int).Exp(g3, privB, dhP)

	return &prekeyMessage{
		identifier:  ident,
		instanceTag: tag,
		y:           y.Pub.K(),
		b:           pubB,
	}, y, privB, pubB
}

func (pp *prekeyProfile) Equals(other *prekeyProfile) bool {
	return bytes.Equal(pp.serialize(), other.serialize())
}

func (pm *prekeyMessage) Equals(other *prekeyMessage) bool {
	return bytes.Equal(pm.serialize(), other.serialize())
}

func (pp *prekeyProfile) generateSignature(kp *gotrax.Keypair) [114]byte {
	msg := pp.serializeForSignature()
	return ed448.DSASign(kp.Sym, kp.Pub.K(), msg)
}

func (pp *prekeyProfile) validate(tag uint32, pub *gotrax.PublicKey) error {
	if pp.instanceTag != tag {
		return errors.New("invalid instance tag in prekey profile")
	}

	if !ed448.DSAVerify(pp.sig.S(), pub.K(), pp.serializeForSignature()) {
		return errors.New("invalid signature in prekey profile")
	}

	if pp.expiration.Before(time.Now()) {
		return errors.New("prekey profile has expired")
	}

	if gotrax.ValidatePoint(pp.sharedPrekey.K()) != nil {
		return errors.New("prekey profile shared prekey is not a valid point")
	}

	return nil
}

func (pm *prekeyMessage) validate(tag uint32) error {
	if pm.instanceTag != tag {
		return errors.New("invalid instance tag in prekey message")
	}

	if gotrax.ValidatePoint(pm.y) != nil {
		return errors.New("prekey profile Y point is not a valid point")
	}

	if validateDHValue(pm.b) != nil {
		return errors.New("prekey profile B value is not a valid DH group member")
	}

	return nil
}

func (pp *prekeyProfile) hasExpired() bool {
	return pp.expiration.Before(time.Now())
}
