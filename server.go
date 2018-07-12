package prekeyserver

import (
	"encoding/base64"
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
	sessions map[string]*realSession

	storageImpl storage

	sessionTimeout time.Duration
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
	toRemove := []string{}
	for nm, s := range g.sessions {
		if s.hasExpired(g.sessionTimeout) {
			toRemove = append(toRemove, nm)
		}
	}
	for _, nm := range toRemove {
		delete(g.sessions, nm)
	}

	// TODO: implement
	// Clean up
	//  - Clean up fragmented message that never got complete
	//  - Remove from storage all expired things
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

func (g *GenericServer) compositeIdentity() []byte {
	return appendData(appendData(nil, []byte(g.identity)), g.fingerprint[:])
}

func (g *GenericServer) session(from string) session {
	if g.sessions == nil {
		g.sessions = make(map[string]*realSession)
	}
	s, ok := g.sessions[from]
	if !ok {
		s = &realSession{}
		g.sessions[from] = s
	}
	return s
}

func (g *GenericServer) sessionComplete(from string) {
	if g.sessions == nil {
		return
	}
	delete(g.sessions, from)
}

func (g *GenericServer) hasSession(from string) bool {
	if g.sessions == nil {
		return false
	}
	_, ok := g.sessions[from]
	return ok
}
