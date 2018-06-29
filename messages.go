package prekeyserver

type messageHandler interface {
	handleMessage(s *GenericServer, from string, message []byte) ([]byte, error)
}

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

type storageInformationRequestMessage struct {
	// Protocol version (SHORT)
	//   The version number of this protocol is 0x0004.

	// Message type (BYTE)
	//   This message has type 0x05.

	// Storage Information MAC (MAC)
	//   The MAC with the appropriate MAC key of the message type.
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

type ensembleRetrievalQueryMessage struct {
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

type ensembleRetrievalMessage struct {
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

type noPrekeyEnsemblesMessage struct {
	// Message type (BYTE)
	//   The message has type 0x11.

	// Receiver instance tag (INT)
	//   The instance tag of the intended recipient.

	// No Prekey-Messages message (DATA)
	//   The human-readable details of this message. It contains the string "No Prekey
	//   Messages available for this identity".
}
