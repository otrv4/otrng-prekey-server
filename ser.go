package prekeyserver

import (
	"time"

	"github.com/otrv4/gotrx"
)

type serializable interface {
	deserialize([]byte) ([]byte, bool)
	serialize() []byte
}

func (m *dake1Message) deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	buf, v, ok := gotrx.ExtractShort(buf)
	if !ok || v != version {
		return buf, false
	}

	if len(buf) < 1 || buf[0] != messageTypeDAKE1 {
		return buf, false
	}
	buf = buf[1:]

	buf, m.instanceTag, ok = gotrx.ExtractWord(buf)
	if !ok {
		return buf, false
	}

	m.clientProfile = &gotrx.ClientProfile{}
	buf, ok = m.clientProfile.Deserialize(buf)
	if !ok {
		return buf, false
	}

	buf, m.i, ok = gotrx.DeserializePoint(buf)
	if !ok {
		return buf, false
	}

	return buf, true
}

func (m *dake1Message) serialize() []byte {
	out := gotrx.AppendShort(nil, version)
	out = append(out, messageTypeDAKE1)
	out = gotrx.AppendWord(out, m.instanceTag)
	out = append(out, m.clientProfile.Serialize()...)
	out = append(out, gotrx.SerializePoint(m.i)...)
	return out
}

func (m *dake2Message) serialize() []byte {
	out := gotrx.AppendShort(nil, version)
	out = append(out, messageTypeDAKE2)
	out = gotrx.AppendWord(out, m.instanceTag)
	out = gotrx.AppendData(out, m.serverIdentity)
	sk := gotrx.CreatePublicKey(m.serverKey, gotrx.Ed448Key)
	out = append(out, sk.Serialize()...)
	out = append(out, gotrx.SerializePoint(m.s)...)
	out = append(out, m.sigma.Serialize()...)
	return out
}

func (m *dake2Message) deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	buf, v, ok := gotrx.ExtractShort(buf)
	if !ok || v != version {
		return buf, false
	}

	if len(buf) < 1 || buf[0] != messageTypeDAKE2 {
		return buf, false
	}
	buf = buf[1:]

	if buf, m.instanceTag, ok = gotrx.ExtractWord(buf); !ok {
		return nil, false
	}

	if buf, m.serverIdentity, ok = gotrx.ExtractData(buf); !ok {
		return nil, false
	}

	sk := gotrx.CreatePublicKey(nil, gotrx.Ed448Key)
	if buf, ok = sk.Deserialize(buf); !ok {
		return nil, false
	}
	m.serverKey = sk.K()

	if buf, m.s, ok = gotrx.DeserializePoint(buf); !ok {
		return nil, false
	}

	m.sigma = &gotrx.RingSignature{}
	if buf, ok = m.sigma.Deserialize(buf); !ok {
		return nil, false
	}

	return buf, true
}

func (m *dake3Message) serialize() []byte {
	out := gotrx.AppendShort(nil, version)
	out = append(out, messageTypeDAKE3)
	out = gotrx.AppendWord(out, m.instanceTag)
	out = append(out, m.sigma.Serialize()...)
	out = gotrx.AppendData(out, m.message)
	return out
}

func (m *dake3Message) deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	buf, v, ok := gotrx.ExtractShort(buf)
	if !ok || v != version {
		return buf, false
	}

	if len(buf) < 1 || buf[0] != messageTypeDAKE3 {
		return buf, false
	}
	buf = buf[1:]

	if buf, m.instanceTag, ok = gotrx.ExtractWord(buf); !ok {
		return nil, false
	}

	m.sigma = &gotrx.RingSignature{}
	if buf, ok = m.sigma.Deserialize(buf); !ok {
		return nil, false
	}

	if buf, m.message, ok = gotrx.ExtractData(buf); !ok {
		return nil, false
	}

	return buf, true
}

func serializePrekeyMessages(pms []*prekeyMessage) []byte {
	out := []byte{}
	for _, pm := range pms {
		out = append(out, pm.serialize()...)
	}
	return out
}

func (m *publicationMessage) serialize() []byte {
	out := gotrx.AppendShort(nil, version)
	out = append(out, messageTypePublication)
	out = append(out, uint8(len(m.prekeyMessages)))
	out = append(out, serializePrekeyMessages(m.prekeyMessages)...)

	if m.clientProfile != nil {
		out = append(out, uint8(1))
		out = append(out, m.clientProfile.Serialize()...)
	} else {
		out = append(out, uint8(0))
	}

	if m.prekeyProfile != nil {
		out = append(out, uint8(1))
		out = append(out, m.prekeyProfile.serialize()...)
	} else {
		out = append(out, uint8(0))
	}

	if m.prekeyMessageProofEcdh != nil {
		out = append(out, m.prekeyMessageProofEcdh.serialize()...)
	}

	if m.prekeyMessageProofDh != nil {
		out = append(out, m.prekeyMessageProofDh.serialize()...)
	}

	if m.prekeyProfileProofEcdh != nil {
		out = append(out, m.prekeyProfileProofEcdh.serialize()...)
	}

	out = append(out, m.mac[:]...)
	return out
}

func (m *publicationMessage) deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	buf, v, ok := gotrx.ExtractShort(buf)
	if !ok || v != version {
		return nil, false
	}

	if len(buf) < 1 || buf[0] != messageTypePublication {
		return nil, false
	}
	buf = buf[1:]

	var tmp uint8
	if buf, tmp, ok = gotrx.ExtractByte(buf); !ok {
		return nil, false
	}

	m.prekeyMessages = make([]*prekeyMessage, tmp)
	for ix := range m.prekeyMessages {
		m.prekeyMessages[ix] = &prekeyMessage{}
		if buf, ok = m.prekeyMessages[ix].deserialize(buf); !ok {
			return nil, false
		}
	}

	if buf, tmp, ok = gotrx.ExtractByte(buf); !ok || tmp > 1 {
		return nil, false
	}

	if tmp == 1 {
		m.clientProfile = &gotrx.ClientProfile{}
		if buf, ok = m.clientProfile.Deserialize(buf); !ok {
			return nil, false
		}
	}

	if buf, tmp, ok = gotrx.ExtractByte(buf); !ok {
		return nil, false
	}

	if tmp == 1 {
		m.prekeyProfile = &prekeyProfile{}
		if buf, ok = m.prekeyProfile.deserialize(buf); !ok {
			return nil, false
		}
	}

	if len(m.prekeyMessages) > 0 {
		m.prekeyMessageProofEcdh = &ecdhProof{}
		if buf, ok = m.prekeyMessageProofEcdh.deserialize(buf); !ok {
			return nil, false
		}

		m.prekeyMessageProofDh = &dhProof{}
		if buf, ok = m.prekeyMessageProofDh.deserialize(buf); !ok {
			return nil, false
		}
	}

	if m.prekeyProfile != nil {
		m.prekeyProfileProofEcdh = &ecdhProof{}
		if buf, ok = m.prekeyProfileProofEcdh.deserialize(buf); !ok {
			return nil, false
		}
	}

	var tmpb []byte
	if buf, tmpb, ok = gotrx.ExtractFixedData(buf, 64); !ok {
		return nil, false
	}
	copy(m.mac[:], tmpb)

	return buf, true
}

func (m *storageInformationRequestMessage) serialize() []byte {
	out := gotrx.AppendShort(nil, version)
	out = append(out, messageTypeStorageInformationRequest)
	out = append(out, m.mac[:]...)
	return out
}

func (m *storageInformationRequestMessage) deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	buf, v, ok := gotrx.ExtractShort(buf)
	if !ok || v != version {
		return buf, false
	}

	if len(buf) < 1 || buf[0] != messageTypeStorageInformationRequest {
		return buf, false
	}
	buf = buf[1:]

	var tmp []byte
	if buf, tmp, ok = gotrx.ExtractFixedData(buf, 64); !ok {
		return nil, false
	}
	copy(m.mac[:], tmp)

	return buf, true
}

func (m *storageStatusMessage) serialize() []byte {
	out := gotrx.AppendShort(nil, version)
	out = append(out, messageTypeStorageStatusMessage)
	out = gotrx.AppendWord(out, m.instanceTag)
	out = gotrx.AppendWord(out, m.number)
	out = append(out, m.mac[:]...)
	return out
}

func (m *storageStatusMessage) deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	buf, v, ok := gotrx.ExtractShort(buf)
	if !ok || v != version {
		return buf, false
	}

	if len(buf) < 1 || buf[0] != messageTypeStorageStatusMessage {
		return buf, false
	}
	buf = buf[1:]

	if buf, m.instanceTag, ok = gotrx.ExtractWord(buf); !ok {
		return nil, false
	}

	if buf, m.number, ok = gotrx.ExtractWord(buf); !ok {
		return nil, false
	}

	var tmp []byte
	if buf, tmp, ok = gotrx.ExtractFixedData(buf, 64); !ok {
		return nil, false
	}
	copy(m.mac[:], tmp)

	return buf, true
}

func (m *successMessage) serialize() []byte {
	out := gotrx.AppendShort(nil, version)
	out = append(out, messageTypeSuccess)
	out = gotrx.AppendWord(out, m.instanceTag)
	out = append(out, m.mac[:]...)
	return out
}

func (m *successMessage) deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	buf, v, ok := gotrx.ExtractShort(buf)
	if !ok || v != version {
		return buf, false
	}

	if len(buf) < 1 || buf[0] != messageTypeSuccess {
		return buf, false
	}
	buf = buf[1:]

	if buf, m.instanceTag, ok = gotrx.ExtractWord(buf); !ok {
		return nil, false
	}

	var tmp []byte
	if buf, tmp, ok = gotrx.ExtractFixedData(buf, 64); !ok {
		return nil, false
	}
	copy(m.mac[:], tmp)

	return buf, true
}

func (m *failureMessage) serialize() []byte {
	out := gotrx.AppendShort(nil, version)
	out = append(out, messageTypeFailure)
	out = gotrx.AppendWord(out, m.instanceTag)
	out = append(out, m.mac[:]...)
	return out
}

func (m *failureMessage) deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	buf, v, ok := gotrx.ExtractShort(buf)
	if !ok || v != version {
		return buf, false
	}

	if len(buf) < 1 || buf[0] != messageTypeFailure {
		return buf, false
	}
	buf = buf[1:]

	if buf, m.instanceTag, ok = gotrx.ExtractWord(buf); !ok {
		return nil, false
	}

	var tmp []byte
	if buf, tmp, ok = gotrx.ExtractFixedData(buf, 64); !ok {
		return nil, false
	}
	copy(m.mac[:], tmp)

	return buf, true
}

func (m *ensembleRetrievalQueryMessage) serialize() []byte {
	out := gotrx.AppendShort(nil, version)
	out = append(out, messageTypeEnsembleRetrievalQuery)
	out = gotrx.AppendWord(out, m.instanceTag)
	out = gotrx.AppendData(out, []byte(m.identity))
	out = gotrx.AppendData(out, m.versions)
	return out
}

func (m *ensembleRetrievalQueryMessage) deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	buf, v, ok := gotrx.ExtractShort(buf)
	if !ok || v != version {
		return nil, false
	}

	if len(buf) < 1 || buf[0] != messageTypeEnsembleRetrievalQuery {
		return nil, false
	}
	buf = buf[1:]

	if buf, m.instanceTag, ok = gotrx.ExtractWord(buf); !ok {
		return nil, false
	}

	var tmp []byte
	if buf, tmp, ok = gotrx.ExtractData(buf); !ok {
		return nil, false
	}
	m.identity = string(tmp)

	if buf, m.versions, ok = gotrx.ExtractData(buf); !ok {
		return nil, false
	}

	return buf, true
}

func (m *ensembleRetrievalMessage) serialize() []byte {
	out := gotrx.AppendShort(nil, version)
	out = append(out, messageTypeEnsembleRetrieval)
	out = gotrx.AppendWord(out, m.instanceTag)
	out = gotrx.AppendData(out, []byte(m.identity))
	out = append(out, uint8(len(m.ensembles)))
	for _, pe := range m.ensembles {
		out = append(out, pe.serialize()...)
	}

	return out
}

func (m *ensembleRetrievalMessage) deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	buf, v, ok := gotrx.ExtractShort(buf)
	if !ok || v != version {
		return nil, false
	}

	if len(buf) < 1 || buf[0] != messageTypeEnsembleRetrieval {
		return nil, false
	}
	buf = buf[1:]

	if buf, m.instanceTag, ok = gotrx.ExtractWord(buf); !ok {
		return nil, false
	}

	var tmpd []byte
	if buf, tmpd, ok = gotrx.ExtractData(buf); !ok {
		return nil, false
	}
	m.identity = string(tmpd)

	var tmp uint8
	if buf, tmp, ok = gotrx.ExtractByte(buf); !ok || tmp == 0 {
		return nil, false
	}

	m.ensembles = make([]*prekeyEnsemble, tmp)
	for ix := range m.ensembles {
		m.ensembles[ix] = &prekeyEnsemble{}
		if buf, ok = m.ensembles[ix].deserialize(buf); !ok {
			return nil, false
		}
	}

	return buf, true
}

func (m *noPrekeyEnsemblesMessage) serialize() []byte {
	out := gotrx.AppendShort(nil, version)
	out = append(out, messageTypeNoPrekeyEnsembles)
	out = gotrx.AppendWord(out, m.instanceTag)
	out = gotrx.AppendData(out, []byte(m.identity))
	out = gotrx.AppendData(out, []byte(m.message))
	return out
}

func (m *noPrekeyEnsemblesMessage) deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	buf, v, ok := gotrx.ExtractShort(buf)
	if !ok || v != version {
		return nil, false
	}

	if len(buf) < 1 || buf[0] != messageTypeNoPrekeyEnsembles {
		return nil, false
	}
	buf = buf[1:]

	if buf, m.instanceTag, ok = gotrx.ExtractWord(buf); !ok {
		return nil, false
	}

	var tmp []byte
	if buf, tmp, ok = gotrx.ExtractData(buf); !ok {
		return nil, false
	}
	m.identity = string(tmp)

	if buf, tmp, ok = gotrx.ExtractData(buf); !ok {
		return nil, false
	}
	m.message = string(tmp)

	return buf, true
}

func serializeVersions(v []byte) []byte {
	return gotrx.AppendData(nil, v)
}

func serializeExpiry(t time.Time) []byte {
	val := t.Unix()
	return gotrx.AppendLong(nil, uint64(val))
}

func (pp *prekeyProfile) serializeForSignature() []byte {
	var out []byte
	out = gotrx.AppendWord(out, pp.instanceTag)
	out = append(out, serializeExpiry(pp.expiration)...)
	out = append(out, pp.sharedPrekey.Serialize()...)
	return out
}

func (pp *prekeyProfile) serialize() []byte {
	return append(pp.serializeForSignature(), pp.sig.Serialize()...)
}

func (pp *prekeyProfile) deserialize(buf []byte) ([]byte, bool) {
	var ok bool

	if buf, pp.instanceTag, ok = gotrx.ExtractWord(buf); !ok {
		return nil, false
	}

	if buf, pp.expiration, ok = gotrx.ExtractTime(buf); !ok {
		return nil, false
	}

	pp.sharedPrekey = gotrx.CreatePublicKey(nil, gotrx.SharedPrekeyKey)
	if buf, ok = pp.sharedPrekey.Deserialize(buf); !ok {
		return nil, false
	}

	pp.sig = &gotrx.EddsaSignature{}
	if buf, ok = pp.sig.Deserialize(buf); !ok {
		return nil, false
	}

	return buf, true
}

func (pm *prekeyMessage) serialize() []byte {
	out := gotrx.AppendShort(nil, version)
	out = append(out, messageTypePrekeyMessage)
	out = gotrx.AppendWord(out, pm.identifier)
	out = gotrx.AppendWord(out, pm.instanceTag)
	out = append(out, gotrx.SerializePoint(pm.y)...)
	out = gotrx.AppendMPI(out, pm.b)
	return out
}

func (pm *prekeyMessage) deserialize(buf []byte) ([]byte, bool) {
	var ok1 bool
	var v uint16

	if buf, v, ok1 = gotrx.ExtractShort(buf); !ok1 || v != version { // version
		return nil, false
	}

	if len(buf) < 1 || buf[0] != messageTypePrekeyMessage {
		return nil, false
	}
	buf = buf[1:] // message type

	if buf, pm.identifier, ok1 = gotrx.ExtractWord(buf); !ok1 {
		return nil, false
	}

	if buf, pm.instanceTag, ok1 = gotrx.ExtractWord(buf); !ok1 {
		return nil, false
	}

	if buf, pm.y, ok1 = gotrx.DeserializePoint(buf); !ok1 {
		return nil, false
	}

	if buf, pm.b, ok1 = gotrx.ExtractMPI(buf); !ok1 {
		return nil, false
	}

	return buf, true
}

func (pe *prekeyEnsemble) serialize() []byte {
	var out []byte
	out = append(out, pe.cp.Serialize()...)
	out = append(out, pe.pp.serialize()...)
	out = append(out, pe.pm.serialize()...)
	return out
}

func (pe *prekeyEnsemble) deserialize(buf []byte) ([]byte, bool) {
	var ok bool

	pe.cp = &gotrx.ClientProfile{}
	if buf, ok = pe.cp.Deserialize(buf); !ok {
		return nil, false
	}

	pe.pp = &prekeyProfile{}
	if buf, ok = pe.pp.deserialize(buf); !ok {
		return nil, false
	}

	pe.pm = &prekeyMessage{}
	if buf, ok = pe.pm.deserialize(buf); !ok {
		return nil, false
	}

	return buf, true
}
