package main

import "flag"

// These flags represent all the available command line flags
var (
	passwordHash   = flag.String("pwd", "", "If we should generate a password hash instead of running the server")
	listenPort     = flag.Uint("listen-port", 8080, "Port to listen on")
	listenIP       = flag.String("listen-address", "localhost", "Address to listen on")
	connectPort    = flag.Uint("connect-port", 3242, "Port to connect to the raw server on")
	connectIP      = flag.String("connect-address", "localhost", "Address to connect to the raw server on")
	runTLS         = flag.Bool("tls", false, "If TLS should be used for the server")
	filePrivateKey = flag.String("key-file", "", "File where private key is stored for tls")
	fileCert       = flag.String("cert-file", "", "File where certificate is stored for tls")
	bindPath       = flag.String("path", "/prekeys", "Path of the url where server should listen")
	passwordFile   = flag.String("pwd-file", "passwords.asc", "File containing the usernames and passwords, one line for each entry, user:pwd")
)
