package prekeyserver

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/coyim/gotrax"
)

// GenericServer represents the main entry point for the prekey server functionality.
type GenericServer struct {
	// The identity, for example prekey.example.org
	identity string
	// The fingerprint of the long term key for the server
	fingerprint gotrax.Fingerprint

	key *gotrax.Keypair

	// Should be minimum 48, since the max envelope size is 47
	fragLen        int
	fragmentations *gotrax.Fragmentor

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

	if g.fragmentations.IsFragment(message) {
		m, c, e := g.fragmentations.NewFragmentReceived(from, message)
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

	msgs := g.fragmentations.PotentiallyFragment(encoded, g.fragLen, 0xDEAD, 0xBEEF, g)

	g.cleanupAfter()

	return msgs, nil
}

func (g *GenericServer) cleanupAfter() {
	g.sessions.cleanup(g.sessionTimeout)
	g.fragmentations.Cleanup(g.fragmentationTimeout)
	g.storageImpl.cleanup()
}

func (g *GenericServer) compositeIdentity() []byte {
	fmt.Printf("string identity %s \n", g.identity)
	fmt.Printf("byte identity %x \n", []byte(g.identity))
	fmt.Printf("appended byte identity %x \n", append(gotrax.AppendData(nil, []byte(g.identity))))
	return append(gotrax.AppendData(nil, []byte(g.identity)))
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
