package gotrax

import (
	"bytes"
	"crypto/dsa"
	"errors"
	"time"

	"github.com/otrv4/ed448"
)

type ClientProfile struct {
	InstanceTag           uint32
	PublicKey             *PublicKey
	ForgingKey            *PublicKey
	Versions              []byte
	Expiration            time.Time
	DsaKey                *dsa.PublicKey
	TransitionalSignature []byte
	Sig                   *EddsaSignature
}

func (m *ClientProfile) Validate(tag uint32) error {
	if m.InstanceTag != tag {
		return errors.New("invalid instance tag in client profile")
	}

	if m.PublicKey == nil {
		return errors.New("missing public key in client profile")
	}

	if m.ForgingKey == nil {
		return errors.New("missing forging key in client profile")
	}

	if m.Sig == nil {
		return errors.New("missing signature in client profile")
	}

	if !ed448.DSAVerify(m.Sig.s, m.PublicKey.k, m.SerializeForSignature()) {
		return errors.New("invalid signature in client profile")
	}

	if m.Expiration.Before(time.Now()) {
		return errors.New("client profile has expired")
	}

	if !bytes.Contains(m.Versions, []byte{'4'}) {
		return errors.New("client profile doesn't support version 4")
	}

	// This branch will be untested for now, since I have NO idea how to generate
	// a valid private key AND eddsa signature that matches an invalid point...
	if ValidatePoint(m.PublicKey.k) != nil {
		return errors.New("client profile public key is not a valid point")
	}

	// See comment above about validating the point
	if ValidatePoint(m.ForgingKey.k) != nil {
		return errors.New("client profile forging key is not a valid point")
	}

	// The spec says to verify the DSA transitional signature here
	// For now, I'll avoid doing that, since the purpose of the transitional
	// signature has nothing to do with the prekey server

	return nil
}

func (m *ClientProfile) Equals(other *ClientProfile) bool {
	return bytes.Equal(m.Serialize(), other.Serialize())
}

func (m *ClientProfile) GenerateSignature(kp *Keypair) [114]byte {
	msg := m.SerializeForSignature()
	return ed448.DSASign(kp.Sym, kp.Pub.k, msg)
}

func (m *ClientProfile) HasExpired() bool {
	return m.Expiration.Before(time.Now())
}
