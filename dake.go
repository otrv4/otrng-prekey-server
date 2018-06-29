package prekeyserver

type dake1Message struct {
	// Protocol version (SHORT)
	//   The version number of this OTR protocol is 0x0004.

	// Message type (BYTE)
	//   The message has type 0x01.

	// Sender instance tag (INT)
	//   The instance tag of the client sending this message.

	// Sender Client Profile (CLIENT-PROF)
	//   As described in the section "Creating a Client Profile" of the OTRv4
	//   specification.

	// I (POINT)
	// 	The ephemeral public ECDH key.
}

func (m *dake1Message) parseMe([]byte) error {
	panic("implement me")
	return nil
}

type dake2Message struct {
	// Protocol version (SHORT)
	//   The version number of this OTR protocol is 0x0004.

	// Message type (BYTE)
	//   The message has type 0x02.

	// Receiver instance tag (INT)
	//   The instance tag of the intended recipient.

	// Prekey Server Composite Identity (PREKEY-SERVER-COMP-ID)
	//   As described in the section "Prekey Server Composite Identity".

	// S (POINT)
	//   The ephemeral public ECDH key.

	// sigma (RING-SIG)
	//   The 'RING-SIG' proof of authentication value.
}

func (m *dake2Message) parseMe([]byte) error {
	panic("implement me")
	return nil
}

type dake3Message struct {
	// Protocol version (SHORT)
	//   The version number of this OTR protocol is 0x0004.

	// Message type (BYTE)
	//   The message has type 0x03.

	// Sender instance tag (INT)
	//   The instance tag of the person sending this message.

	// sigma (RING-SIG)
	//   The 'RING-SIG' proof of authentication value.

	// Message (DATA)
	//   The message sent to the Prekey Server.
	//   In this protocol there are 2 kinds of messages that can be sent:
	//     - Prekey Publication
	//     - Storage Information Request
}

func (m *dake3Message) parseMe([]byte) error {
	panic("implement me")
	return nil
}
