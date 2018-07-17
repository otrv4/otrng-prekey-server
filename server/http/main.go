package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"

	"golang.org/x/crypto/scrypt"
)

func loadUsers() {
	users = make(map[string][]byte)
	dd, e := ioutil.ReadFile(*passwordFile)
	if e != nil {
		return
	}
	rr := bufio.NewReader(bytes.NewBuffer(dd))
	for {
		s, e := rr.ReadString('\n')
		if s != "" {
			s = s[:len(s)-1]
			up := strings.SplitN(s, ":", 2)
			decoded, _ := base64.StdEncoding.DecodeString(up[1])
			users[up[0]] = decoded
		}
		if e != nil {
			return
		}
	}
}

var users map[string][]byte

func main() {
	flag.Parse()

	if *passwordHash != "" {
		fmt.Println(base64.StdEncoding.EncodeToString(h(*passwordHash)))
		return
	}

	loadUsers()

	handler := http.NewServeMux()
	handler.HandleFunc(*bindPath, prekeyHandler)

	addr := net.JoinHostPort(*listenIP, fmt.Sprintf("%d", *listenPort))

	if !*runTLS {
		http.ListenAndServe(addr, handler)
	} else {
		http.ListenAndServeTLS(addr, *fileCert, *filePrivateKey, handler)
	}
}

var hashSalt = []byte{0xDD, 0x59, 0x1B, 0x22, 0xDE, 0xAC, 0x5B, 0xDA}

func h(s string) []byte {
	val, _ := scrypt.Key([]byte(s), hashSalt, 1<<15, 8, 1, 32)
	return val[:]
}

func getPwdFor(u string) ([]byte, bool) {
	return users[u], true
}

func prekeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	u, p, ok := r.BasicAuth()

	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="prekey server"`)
		http.Error(w, "Unauthorized.", http.StatusUnauthorized)
		return
	}

	p2, ok2 := getPwdFor(u)
	if !(ok2 && bytes.Equal(h(p), p2)) {
		w.Header().Set("WWW-Authenticate", `Basic realm="prekey server"`)
		http.Error(w, "Unauthorized.", http.StatusUnauthorized)
		return
	}

	bod, _ := ioutil.ReadAll(r.Body)
	res := getPrekeyResponseFromRealServer(u, bod)
	w.Write(res)
}

func getPrekeyResponseFromRealServer(u string, data []byte) []byte {
	addr, _ := net.ResolveTCPAddr("tcp", net.JoinHostPort(*connectIP, fmt.Sprintf("%d", *connectPort)))
	con, _ := net.DialTCP(addr.Network(), nil, addr)
	defer con.Close()

	toSend := []byte{}
	toSend = appendShort(toSend, uint16(len(u)))
	toSend = append(toSend, []byte(u)...)
	toSend = appendShort(toSend, uint16(len(data)))
	toSend = append(toSend, data...)
	con.Write(toSend)
	con.CloseWrite()
	res, _ := ioutil.ReadAll(con)
	res2, ss, _ := extractShort(res)
	if uint16(len(res2)) != ss {
		fmt.Printf("Unexpected length of data received\n")
		return nil
	}
	return res2
}

func appendShort(l []byte, r uint16) []byte {
	return append(l, byte(r>>8), byte(r))
}

func extractShort(d []byte) ([]byte, uint16, bool) {
	if len(d) < 2 {
		return nil, 0, false
	}

	return d[2:], uint16(d[0])<<8 |
		uint16(d[1]), true
}
