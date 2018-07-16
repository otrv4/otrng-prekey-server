package main

import "flag"

// These flags represent all the available command line flags
var (
	keyFile              = flag.String("key-file", "raw-server.keys", "Location of file where server long term keys should be stored and loaded")
	listenPort           = flag.Uint("port", 3242, "Port to listen to")
	listenIP             = flag.String("address", "localhost", "Address to listen to")
	storageEngine        = flag.String("storage", "in-memory", "What storage engine to use: 'in-memory' or 'dir:/PATH/HERE' are the choices available")
	serverIdentity       = flag.String("identity", "keys.example.org", "The identity of the server")
	fragLen              = flag.Uint("fragmentation-length", 0, "Fragmentation length - 0 means no fragmenting")
	sessionTimeout       = flag.Uint("session-timeout", 5, "Session timeout, in minutes")
	fragmentationTimeout = flag.Uint("fragmentation-timeout", 5, "Fragment timeout, in minutes")
)
