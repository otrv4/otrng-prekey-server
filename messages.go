package prekeyserver

import (
	"errors"
	"fmt"
)

type publicationMessage struct {
	// Protocol version (SHORT)
	//   The version number of this protocol is 0x0004.

	// Message type (BYTE)
	//   This message has type 0x04.

	// N (BYTE)
	//    The number of Prekey Messages present in this message.

	// Prekey Messages (DATA)
	//    All 'N' Prekey Messages serialized according to OTRv4 specification.

	// J (BYTE)
	//    A number that shows if a Client Profile is present or not. If present, set it
	//    to one; otherwise, to zero.

	// Client Profile (CLIENT-PROF)
	//   The Client Profiles created as described in the section "Creating a Client
	//   Profile" of the OTRv4 specification. This value is optional.

	// J (BYTE)
	//    The number of Prekey Profiles present in this message. If there are none,
	//    the value is zero.

	// Prekey Profiles (PREKEY-PROF)
	//   All 'J' Prekey Profiles created as described in the section "Creating a Prekey
	//   Profile" of the OTRv4 specification.

	// Prekey MAC (MAC)
	//   The MAC with the appropriate MAC key of everything: from the message type to
	// 	the Prekey Profiles, if present.
}

func (m *publicationMessage) parseMe([]byte) error {
	panic("implement me")
	return nil
}

type storageInformationRequestMessage struct {
	// Protocol version (SHORT)
	//   The version number of this protocol is 0x0004.

	// Message type (BYTE)
	//   This message has type 0x05.

	// Storage Information MAC (MAC)
	//   The MAC with the appropriate MAC key of the message type.
}

func (m *storageInformationRequestMessage) parseMe([]byte) error {
	panic("implement me")
	return nil
}

type storageStatusMessage struct {
	// Protocol version (SHORT)
	//   The version number of this protocol is 0x0004.

	// Message type (BYTE)
	//   The message has type 0x06.

	// Receiver instance tag (INT)
	//   The instance tag of the intended recipient.

	// Stored prekey messages number (INT)
	//   The number of prekey messages stored in the Prekey Server for the
	//   long-term public key and instance tag used during the DAKE.

	// Status MAC (MAC)
	//   The MAC with the appropriate MAC key of everything: from the message type to
	//   the stored prekey messages number.
}

func (m *storageStatusMessage) parseMe([]byte) error {
	panic("implement me")
	return nil
}

type successMessage struct {
	// Protocol version (SHORT)
	//   The version number of this protocol is 0x0004.

	// Message type (BYTE)
	//   The message has type 0x07.

	// Receiver instance tag (INT)
	//   The instance tag of the intended recipient.

	// Success MAC (MAC)
	//   The MAC with the appropriate MAC key of everything: from the message type to
	// 	the Success message.
}

func (m *successMessage) parseMe([]byte) error {
	panic("implement me")
	return nil
}

type failureMessage struct {
	// Protocol version (SHORT)
	//   The version number of this protocol is 0x0004.

	// Message type (BYTE)
	//   The message has type 0x08.

	// Receiver instance tag (INT)
	//   The instance tag of the intended recipient.

	// Failure MAC (MAC)
	//   The MAC with the appropriate MAC key of everything: from the message type to
	//   the Failure message.
}

func (m *failureMessage) parseMe([]byte) error {
	panic("implement me")
	return nil
}

type ensembleRetrievalQueryMessage struct {
	// Protocol version (SHORT)
	//   The version number of this OTR protocol is 0x0004.

	// Message type (BYTE)
	//   The message has type 0x09.

	// Sender instance tag (INT)
	//   The instance tag of the sender.

	// Participant Identity (DATA)
	//   The identity of the participant you are asking Prekey Ensembles for. In the
	//   case of XMPP, for example, this is the bare jid.

	// Versions (DATA)
	//   The OTR versions you are asking Prekey Ensembles for. A valid versions string
	//   can be created by concatenating the version numbers together in any order.
	//   For example, a user who wants Prekey Ensembles for versions 4 and 5 will have
	//   the 2-byte version string "45" or "54". Unrecognized versions should be
	//   ignored.
}

func (m *ensembleRetrievalQueryMessage) parseMe([]byte) error {
	panic("implement me")
	return nil
}

type ensembleRetrievalMessage struct {
	// Protocol version (SHORT)
	//   The version number of this OTR protocol is 0x0004.

	// Message type (BYTE)
	//   The message has type 0x10.

	// Receiver instance tag (INT)
	//   The instance tag of the intended recipient.

	// L (INT)
	//   The number of Prekey Ensembles

	// Ensembles (DATA)
	//   The concatenated Prekey Ensembles. Each Ensemble is encoded as:

	//    Client Profile (CLIENT-PROF)
	//    Prekey Profile (PREKEY-PROF)
	//    Prekey Message
	//       Prekey Messages are encoded as specified in OTRv4 specification, section
	//       'Prekey Message'.
}

func (m *ensembleRetrievalMessage) parseMe([]byte) error {
	panic("implement me")
	return nil
}

type noPrekeyEnsemblesMessage struct {
	// Protocol version (SHORT)
	//   The version number of this OTR protocol is 0x0004.

	// Message type (BYTE)
	//   The message has type 0x11.

	// Receiver instance tag (INT)
	//   The instance tag of the intended recipient.

	// No Prekey-Messages message (DATA)
	//   The human-readable details of this message. It contains the string "No Prekey
	//   Messages available for this identity".
}

func (m *noPrekeyEnsemblesMessage) parseMe([]byte) error {
	panic("implement me")
	return nil
}

type parseable interface {
	parseMe([]byte) error
}

var (
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
)

const indexOfMessageType = 2

func parseMessage(message []byte) (interface{}, error) {
	if len(message) <= indexOfMessageType {
		return nil, errors.New("message too short to be a valid message")
	}

	messageType := message[indexOfMessageType]

	var r parseable
	switch messageType {
	case messageTypeDAKE1:
		r = &dake1Message{}
	case messageTypeDAKE2:
		r = &dake2Message{}
	case messageTypeDAKE3:
		r = &dake3Message{}
	case messageTypePublication:
		r = &publicationMessage{}
	case messageTypeStorageInformationRequest:
		r = &storageInformationRequestMessage{}
	case messageTypeStorageStatusMessage:
		r = &storageStatusMessage{}
	case messageTypeSuccess:
		r = &successMessage{}
	case messageTypeFailure:
		r = &failureMessage{}
	case messageTypeEnsembleRetrievalQuery:
		r = &ensembleRetrievalQueryMessage{}
	case messageTypeEnsembleRetrieval:
		r = &ensembleRetrievalMessage{}
	case messageTypeNoPrekeyEnsembles:
		r = &noPrekeyEnsemblesMessage{}
	default:
		return nil, fmt.Errorf("unknown message type: 0x%x", messageType)
	}

	return r, r.parseMe(message)
}

// What messages can we as a server receive at the top level?

// DAKE1
// DAKE3
// ensembleRetrievalQueryMessage

// What messages are NOT top level?
//    publicationMessage
//    storageInformationRequestMessage

// What messages can we as a server SEND:
// DAKE2
// storageStatusMessage
// successMessage
// failureMessage
// ensembleRetrievalMessage
// noPrekeyEnsemblesMessage
