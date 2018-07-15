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
	var ok bool
	var l uint16
	var from, d []byte

	for len(remaining) > 0 {
		remaining, l, ok = extractShort(remaining)
		if !ok {
			return nil, errors.New("can't parse length of from element")
		}
		remaining, from, ok = extractFixedData(remaining, int(l))
		if !ok {
			return nil, errors.New("can't parse from element")
		}
		remaining, l, ok = extractShort(remaining)
		if !ok {
			return nil, errors.New("can't parse length of data element")
		}
		remaining, d, ok = extractFixedData(remaining, int(l))
		if !ok {
			return nil, errors.New("can't parse data element")
		}
		result = append(result, &protocolElement{from: string(from), data: string(d)})
	}

	return result, nil
}
