package prekeyserver

import "github.com/twstrike/ed448"

type dake1Message struct {
	instanceTag   uint32
	clientProfile *clientProfile
	i             ed448.Point
}

type dake2Message struct {
	instanceTag       uint32
	serverIdentity    []byte
	serverFingerprint fingerprint
	s                 ed448.Point
	sigma             *ringSignature
}

type dake3Message struct {
	instanceTag uint32
	sigma       *ringSignature
	message     []byte // can be either publication or storage information request
}
