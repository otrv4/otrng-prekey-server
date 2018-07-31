package prekeyserver

import (
	"errors"
	"io"
	"time"
)

// GenericServer represents the main entry point for the prekey server functionality.
type GenericServer struct {
	// The identity, for example prekey.example.org
	identity string
	// The fingerprint of the long term key for the server
	fingerprint fingerprint

	key *keypair

	// Should be minimum 48, since the max envelope size is 47
	fragLen        int
	fragmentations *fragmentations

	messageHandler messageHandler

	rand     io.Reader
	sessions *sessionManager

	storageImpl storage

	sessionTimeout       time.Duration
	fragmentationTimeout time.Duration
	rest                 Restrictor
}

func (g *GenericServer) storage() storage {
	return g.storageImpl
}

func (g *GenericServer) handleMessage(from string, message []byte) ([]byte, error) {
	if g.messageHandler != nil {
		return g.messageHandler.handleMessage(from, message)
	}

	panic("programmer error, missing message handler")
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
		m, c, e := g.fragmentations.newFragmentReceived(from, message)
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

	g.cleanupAfter()

	return msgs, nil
}

func (g *GenericServer) cleanupAfter() {
	g.sessions.cleanup(g.sessionTimeout)
	g.fragmentations.cleanup(g.fragmentationTimeout)
	g.storageImpl.cleanup()
}

func (g *GenericServer) compositeIdentity() []byte {
	return append(appendData(nil, []byte(g.identity)), g.key.pub.serialize()...)
}

func (g *GenericServer) session(from string) session {
	return g.sessions.get(from)
}

func (g *GenericServer) sessionComplete(from string) {
	g.sessions.complete(from)
}

func (g *GenericServer) hasSession(from string) bool {
	return g.sessions.has(from)
}
