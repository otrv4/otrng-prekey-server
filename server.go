package prekeyserver

import "errors"

// GenericServer represents the main entry point for the prekey server functionality.
type GenericServer struct {
	// key, fingerprint?
	identity string
	padding  uint
}

// Handle should receive the message in its original form
// Thus, a real server would give the received message as is to this function,
// excluding surrounding whitespace.
// It will return an error if something went wrong, and a list of messages that should be returned
// Each message to return should be sent in a separate network package, back to the original sender
// The Handle function should be called from its own goroutine to ensure asynchronous behavior of the server
func (g *GenericServer) Handle(from, message string) (returns []string, err error) {
	// Check if it's fragmented
	// Decode it from base64
	// Find a possible Session with the sender, or create a new one
	// Figure out which message it us, and get a return
	// Base64 encode the return
	// Fragment the returned message
	// Clean up
	//  - If everything is done, kill Session
	//  - Clean up fragmented message that never got complete
	return nil, errors.New("empty message")
}
