package prekeyserver

import "time"

type clientProfile struct {
	identifier            uint32
	instanceTag           uint32
	publicKey             *publicKey
	versions              []byte
	expiration            time.Time
	dsaKey                []byte
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

func serializeVersions(v []byte) []byte {
	return appendData(nil, v)
}

func serializeExpiry(t time.Time) []byte {
	val := t.Unix()
	return appendLong(nil, uint64(val))
}

const (
	clientProfileTagIdentifier  = uint16(0x0001)
	clientProfileTagInstanceTag = uint16(0x0002)
	clientProfileTagPublicKey   = uint16(0x0003)
	clientProfileTagVersions    = uint16(0x0005)
	clientProfileTagExpiry      = uint16(0x0006)
)

func (cp *clientProfile) serialize() []byte {
	out := []byte{}
	fields := uint32(5)

	// TODO: serialize DSA stuff as well
	// if cp.dsaKey != nil {
	// 	fields++
	// }
	// if cp.transitionalSignature != nil {
	// 	fields++
	// }

	out = appendWord(out, fields)

	out = appendShort(out, clientProfileTagIdentifier)
	out = appendWord(out, cp.identifier)

	out = appendShort(out, clientProfileTagInstanceTag)
	out = appendWord(out, cp.instanceTag)

	out = appendShort(out, clientProfileTagPublicKey)
	out = append(out, cp.publicKey.serialize()...)

	out = appendShort(out, clientProfileTagVersions)
	out = append(out, serializeVersions(cp.versions)...)

	out = appendShort(out, clientProfileTagExpiry)
	out = append(out, serializeExpiry(cp.expiration)...)

	out = append(out, cp.sig.serialize()...)

	return out
}
