package main

import (
	"errors"

	pks "github.com/otrv4/otrng-prekey-server"
)

// This protocol has a fragmentation length of 2**16
// OK, on incoming, what we expect is this:
// - 2 bytes uint16 len1
// - len1 bytes containing the "from"
// - 2 bytes uint16 len2
// - len2 bytes containing the message
// Several of these messages can be coming in in the same TCP packet
// On outgoing, we do the same thing, except we only will send
// data elements, no "from" elements

type protocolElement struct {
	from string
	data string
}

func protocolEncodePacket(inp []byte) []byte {
	return append(appendShort(nil, uint16(len(inp))), inp...)
}

func protocolHandleData(data []byte, s pks.Server) ([]byte, error) {
	res, e := protocolParseData(data)
	if e != nil {
		return nil, e
	}
	result := []byte{}
	for _, pe := range res {
		outp, e := s.Handle(pe.from, pe.data)
		if e != nil {
			return nil, e
		}
		for _, o := range outp {
			result = append(result, protocolEncodePacket([]byte(o))...)
		}
	}
	return result, nil
}

func protocolParseData(data []byte) ([]*protocolElement, error) {
	result := []*protocolElement{}
	remaining := data

	for len(remaining) > 0 {
		remaining, fromLen, ok := extractShort(remaining)
		if !ok {
			return nil, errors.New("blah")
		}
		remaining, from, ok := extractFixedData(remaining, int(fromLen))
		if !ok {
			return nil, errors.New("blah2")
		}
		remaining, dataLen, ok := extractShort(remaining)
		if !ok {
			return nil, errors.New("blah3")
		}
		remaining, d, ok := extractFixedData(remaining, int(dataLen))
		if !ok {
			return nil, errors.New("blah4")
		}
		result = append(result, &protocolElement{from: string(from), data: string(d)})
	}

	return result, nil
}

func extractShort(d []byte) ([]byte, uint16, bool) {
	if len(d) < 2 {
		return nil, 0, false
	}

	return d[2:], uint16(d[0])<<8 |
		uint16(d[1]), true
}

func extractFixedData(d []byte, l int) (newPoint []byte, data []byte, ok bool) {
	if len(d) < l {
		return d, nil, false
	}
	return d[l:], d[0:l], true
}

func appendShort(l []byte, r uint16) []byte {
	return append(l, byte(r>>8), byte(r))
}
