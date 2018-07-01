package prekeyserver

func appendWord(l []byte, r uint32) []byte {
	return append(l, byte(r>>24), byte(r>>16), byte(r>>8), byte(r))
}

func appendShort(l []byte, r uint16) []byte {
	return append(l, byte(r>>8), byte(r))
}

func appendLong(l []byte, r uint64) []byte {
	return append(l, byte(r>>56), byte(r>>48), byte(r>>40), byte(r>>32),
		byte(r>>24), byte(r>>16), byte(r>>8), byte(r))
}

func appendData(l, r []byte) []byte {
	return append(appendWord(l, uint32(len(r))), r...)
}

func extractShort(d []byte) ([]byte, uint16, bool) {
	if len(d) < 2 {
		return nil, 0, false
	}

	return d[2:], uint16(d[0])<<8 |
		uint16(d[1]), true
}
