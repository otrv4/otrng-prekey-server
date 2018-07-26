package prekeyserver

// Restrictor is a function that will return true if the
// given from-name is not acceptable to this server.
// The default will return false for anything, thus allowing all from-names
type Restrictor func(string) bool

func nullRestrictor(from string) bool {
	return false
}
