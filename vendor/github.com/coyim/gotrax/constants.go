package gotrax

import "github.com/otrv4/ed448"

var DsaKeyType = []byte{0x00, 0x00}
var Ed448KeyType = []byte{0x00, 0x10}
var Ed448KeyTypeInt = uint16(0x0010)
var SharedPrekeyKeyType = []byte{0x00, 0x11}
var SharedPrekeyKeyTypeInt = uint16(0x0011)

const SymKeyLength = 57
const PrivKeyLength = 57
const FingerprintLength = 56
const SkLength = 64

var IdentityPoint = ed448.NewPoint([16]uint32{0x00}, [16]uint32{0x01}, [16]uint32{0x01}, [16]uint32{0x00})

const (
	ClientProfileTagInstanceTag           = uint16(0x0001)
	ClientProfileTagPublicKey             = uint16(0x0002)
	ClientProfileTagVersions              = uint16(0x0004)
	ClientProfileTagExpiry                = uint16(0x0005)
	ClientProfileTagDSAKey                = uint16(0x0006)
	ClientProfileTagTransitionalSignature = uint16(0x0008)
)

var kdfPrekeyServerPrefix = []byte("OTR-Prekey-Server")
var kdfPrefix = []byte("OTRv4")

const (
	usageFingerprint = 0x00
)
