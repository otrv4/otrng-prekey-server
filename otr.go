package prekeyserver

import (
	"bytes"
	"crypto/rand"
	"errors"
	"math/big"
	"time"

	"github.com/otrv4/ed448"
	"github.com/otrv4/gotrx"
)

type prekeyProfile struct {
	instanceTag  uint32
	expiration   time.Time
	sharedPrekey *gotrx.PublicKey
	sig          *gotrx.EddsaSignature
}

type prekeyMessage struct {
	identifier  uint32
	instanceTag uint32
	y           ed448.Point
	b           *big.Int
}

type prekeyEnsemble struct {
	cp *gotrx.ClientProfile
	pp *prekeyProfile
	pm *prekeyMessage
}

func generatePrekeyProfile(wr gotrx.WithRandom, tag uint32, expiration time.Time, longTerm *gotrx.Keypair) (*prekeyProfile, *gotrx.Keypair) {
	sharedKey := gotrx.GenerateKeypair(wr)
	sharedKey.Pub = gotrx.CreatePublicKey(sharedKey.Pub.K(), gotrx.SharedPrekeyKey)
	pp := &prekeyProfile{
		instanceTag:  tag,
		expiration:   expiration,
		sharedPrekey: sharedKey.Pub,
	}

	pp.sig = gotrx.CreateEddsaSignature(pp.generateSignature(longTerm))

	return pp, sharedKey
}

func generatePrekeyMessage(wr gotrx.WithRandom, tag uint32) (*prekeyMessage, *gotrx.Keypair, *big.Int, *big.Int) {
	ident := gotrx.RandomUint32(wr)
	y := gotrx.GenerateKeypair(wr)
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

func (pp *prekeyProfile) generateSignature(kp *gotrx.Keypair) [114]byte {
	msg := pp.serializeForSignature()
	return ed448.DSASign(kp.Sym, kp.Pub.K(), msg)
}

func (pp *prekeyProfile) validate(tag uint32, pub *gotrx.PublicKey) error {
	if pp.instanceTag != tag {
		return errors.New("invalid instance tag in prekey profile")
	}

	if !ed448.DSAVerify(pp.sig.S(), pub.K(), pp.serializeForSignature()) {
		return errors.New("invalid signature in prekey profile")
	}

	if pp.expiration.Before(time.Now()) {
		return errors.New("prekey profile has expired")
	}

	if gotrx.ValidatePoint(pp.sharedPrekey.K()) != nil {
		return errors.New("prekey profile shared prekey is not a valid point")
	}

	return nil
}

func (pm *prekeyMessage) validate(tag uint32) error {
	if pm.instanceTag != tag {
		return errors.New("invalid instance tag in prekey message")
	}

	if gotrx.ValidatePoint(pm.y) != nil {
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
