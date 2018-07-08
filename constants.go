package prekeyserver

import (
	"errors"

	"github.com/otrv4/ed448"
)

var dsaKeyType = []byte{0x00, 0x00}

const (
	clientProfileTagIdentifier            = uint16(0x0001)
	clientProfileTagInstanceTag           = uint16(0x0002)
	clientProfileTagPublicKey             = uint16(0x0003)
	clientProfileTagVersions              = uint16(0x0005)
	clientProfileTagExpiry                = uint16(0x0006)
	clientProfileTagDSAKey                = uint16(0x0007)
	clientProfileTagTransitionalSignature = uint16(0x0008)
)

const (
	version          = uint16(4)
	dake1MessageType = uint8(0x01)
	dake2MessageType = uint8(0x02)
	dake3MessageType = uint8(0x03)
)

const fragmentationPrefix = "?OTRP|"

const symKeyLength = 57
const privKeyLength = 57
const fingerprintLength = 56
const skLength = 64

const (
	usageFingerprint                      = 0x00
	usageSK                               = 0x01
	usageInitiatorClientProfile           = 0x02
	usageInitiatorPrekeyCompositeIdentity = 0x03
	usageInitiatorPrekeyCompositePHI      = 0x04
	usageReceiverClientProfile            = 0x05
	usageReceiverPrekeyCompositeIdentity  = 0x06
	usageReceiverPrekeyCompositePHI       = 0x07
	usagePreMACKey                        = 0x08
	usagePreMAC                           = 0x09
	usageStorageInfoMAC                   = 0x0A
	usageStatusMAC                        = 0x0B
	usageSuccessMAC                       = 0x0C
	usageFailureMAC                       = 0x0D
	usagePrekeyMessage                    = 0x0E
	usageClientProfile                    = 0x0F
	usagePrekeyProfile                    = 0x10
)

const macLength = 64

const (
	messageTypeDAKE1                     = uint8(0x01)
	messageTypeDAKE2                     = uint8(0x02)
	messageTypeDAKE3                     = uint8(0x03)
	messageTypePublication               = uint8(0x04)
	messageTypeStorageInformationRequest = uint8(0x05)
	messageTypeStorageStatusMessage      = uint8(0x06)
	messageTypeSuccess                   = uint8(0x07)
	messageTypeFailure                   = uint8(0x08)
	messageTypeEnsembleRetrievalQuery    = uint8(0x09)
	messageTypeEnsembleRetrieval         = uint8(0x10)
	messageTypeNoPrekeyEnsembles         = uint8(0x11)
	messageTypePrekeyMessage             = uint8(0x0F)
)

const noPrekeyMessagesAvailableMessage = "No Prekey Messages available for this identity"

const indexOfMessageType = 2

var One ed448.Scalar
var OneFourth ed448.Scalar
var identityPoint = ed448.NewPoint([16]uint32{0x00}, [16]uint32{0x01}, [16]uint32{0x01}, [16]uint32{0x00})

var errShortRandomRead = errors.New("short read from random source")

var base_point_bytes_dup = []byte{
	0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
	0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
	0x66, 0x66, 0x66, 0x66, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
	0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
	0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x00,
}

var prime_order_bytes_dup = []byte{
	0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0x7c, 0xca, 0x23, 0xe9, 0xc4, 0x4e, 0xdb, 0x49,
	0xae, 0xd6, 0x36, 0x90, 0x21, 0x6c, 0xc2, 0x72, 0x8d, 0xc5, 0x8f, 0x55,
	0x23, 0x78, 0xc2, 0x92, 0xab, 0x58, 0x44, 0xf3,
}

func init() {
	oneBuf := [privKeyLength]byte{0x01}
	One = ed448.NewScalar(oneBuf[:])
	OneFourth = ed448.NewScalar(oneBuf[:])
	OneFourth.Halve(OneFourth)
	OneFourth.Halve(OneFourth)
}
