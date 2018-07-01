package prekeyserver

import (
	"encoding/base64"
	"errors"
	"io"
)

// GenericServer represents the main entry point for the prekey server functionality.
type GenericServer struct {
	// The identity, for example prekey.example.org
	identity string
	// The fingerprint of the long term key for the server
	fingerprint fingerprint

	key *keypair

	fragLen        int
	fragmentations *fragmentations

	messageHandler messageHandler

	rand io.Reader
}

func (g *GenericServer) handleMessage(from string, message []byte) ([]byte, error) {
	if g.messageHandler != nil {
		return g.messageHandler.handleMessage(from, message)
	}

	//	panic("programmer error, missing message handler")
	return []byte(""), nil
}

// Handle should receive the message in its original form
// Thus, a real server would give the received message as is to this function,
// excluding surrounding whitespace.
// It will return an error if something went wrong, and a list of messages that should be returned
// Each message to return should be sent in a separate network package, back to the original sender
// The Handle function should be called from its own goroutine to ensure asynchronous behavior of the server
func (g *GenericServer) Handle(from, message string) (returns []string, err error) {
	if message == "" {
		return nil, errors.New("empty message")
	}

	if isFragment(message) {
		m, c, e := g.fragmentations.newFragmentReceived(message)
		if e != nil {
			return nil, e
		}
		if !c {
			return nil, nil
		}
		message = m
	}

	if message[len(message)-1] != '.' {
		return nil, errors.New("invalid message format - missing ending punctuation")
	}

	decoded, ok := decodeMessage(message[:len(message)-1])
	if !ok {
		return nil, errors.New("invalid message format - corrupted base64 encoding")
	}

	msg, e := g.handleMessage(from, decoded)
	if e != nil {
		return nil, e
	}

	encoded := encodeMessage(msg) + "."

	msgs := potentiallyFragment(encoded, g.fragLen, g)

	g.cleanupAfter(from)

	return msgs, nil
}

func (g *GenericServer) cleanupAfter(from string) {
	// Clean up
	//  - If everything is done, kill Session
	//  - Clean up fragmented message that never got complete
}

func decodeMessage(inp string) ([]byte, bool) {
	decoded, err := base64.StdEncoding.DecodeString(inp)
	if err != nil {
		return nil, false
	}
	return decoded, true
}

func encodeMessage(inp []byte) string {
	return base64.StdEncoding.EncodeToString(inp)
}
