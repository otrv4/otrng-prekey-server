package prekeyserver

import (
	"errors"

	"github.com/otrv4/ed448"
)

var dsaKeyType = []byte{0x00, 0x00}
var ed448KeyType = []byte{0x00, 0x10}
var ed448KeyTypeInt = uint16(0x0010)
var sharedPrekeyKeyType = []byte{0x00, 0x11}
var sharedPrekeyKeyTypeInt = uint16(0x0011)

const (
	clientProfileTagInstanceTag           = uint16(0x0001)
	clientProfileTagPublicKey             = uint16(0x0002)
	clientProfileTagVersions              = uint16(0x0004)
	clientProfileTagExpiry                = uint16(0x0005)
	clientProfileTagDSAKey                = uint16(0x0006)
	clientProfileTagTransitionalSignature = uint16(0x0008)
)

const (
	version = uint16(4)
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
	usageAuth                             = 0x11
)

const macLength = 64

const (
	messageTypeDAKE1                     = uint8(0x35)
	messageTypeDAKE2                     = uint8(0x36)
	messageTypeDAKE3                     = uint8(0x37)
	messageTypePublication               = uint8(0x08)
	messageTypeStorageInformationRequest = uint8(0x09)
	messageTypeStorageStatusMessage      = uint8(0x0B)
	messageTypeSuccess                   = uint8(0x06)
	messageTypeFailure                   = uint8(0x05)
	messageTypeEnsembleRetrievalQuery    = uint8(0x10)
	messageTypeEnsembleRetrieval         = uint8(0x13)
	messageTypeNoPrekeyEnsembles         = uint8(0x0E)
	messageTypePrekeyMessage             = uint8(0x0F)
)

const noPrekeyMessagesAvailableMessage = "No Prekey Messages available for this identity"

const indexOfMessageType = 2

var identityPoint = ed448.NewPoint([16]uint32{0x00}, [16]uint32{0x01}, [16]uint32{0x01}, [16]uint32{0x00})

var errShortRandomRead = errors.New("short read from random source")

var basePointBytesDup = []byte{
	0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
	0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
	0x66, 0x66, 0x66, 0x66, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
	0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
	0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x00,
}

var primeOrderBytesDup = []byte{
	0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0x7c, 0xca, 0x23, 0xe9, 0xc4, 0x4e, 0xdb, 0x49,
	0xae, 0xd6, 0x36, 0x90, 0x21, 0x6c, 0xc2, 0x72, 0x8d, 0xc5, 0x8f, 0x55,
	0x23, 0x78, 0xc2, 0x92, 0xab, 0x58, 0x44, 0xf3,
}
