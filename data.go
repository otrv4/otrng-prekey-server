package prekeyserver

import (
	"math/big"
	"time"
)

func serializeWord(r uint32) []byte {
	return []byte{byte(r >> 24), byte(r >> 16), byte(r >> 8), byte(r)}
}

func appendWord(l []byte, r uint32) []byte {
	return append(l, serializeWord(r)...)
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

func appendMPI(l []byte, r *big.Int) []byte {
	return appendData(l, r.Bytes())
}

func extractByte(d []byte) ([]byte, uint8, bool) {
	if len(d) < 1 {
		return nil, 0, false
	}

	return d[1:], uint8(d[0]), true
}

func extractShort(d []byte) ([]byte, uint16, bool) {
	if len(d) < 2 {
		return nil, 0, false
	}

	return d[2:], uint16(d[0])<<8 |
		uint16(d[1]), true
}

func extractWord(d []byte) ([]byte, uint32, bool) {
	if len(d) < 4 {
		return nil, 0, false
	}

	return d[4:], uint32(d[0])<<24 |
		uint32(d[1])<<16 |
		uint32(d[2])<<8 |
		uint32(d[3]), true
}

func extractDoubleWord(d []byte) ([]byte, uint64, bool) {
	if len(d) < 8 {
		return nil, 0, false
	}

	return d[8:], uint64(d[0])<<56 |
		uint64(d[1])<<48 |
		uint64(d[2])<<40 |
		uint64(d[3])<<32 |
		uint64(d[4])<<24 |
		uint64(d[5])<<16 |
		uint64(d[6])<<8 |
		uint64(d[7]), true
}

func extractData(d []byte) (newPoint []byte, data []byte, ok bool) {
	newPoint, length, ok := extractWord(d)
	if !ok || len(newPoint) < int(length) {
		return d, nil, false
	}

	data = newPoint[:int(length)]
	newPoint = newPoint[int(length):]
	ok = true
	return
}

func extractTime(d []byte) (newPoint []byte, t time.Time, ok bool) {
	newPoint, tt, ok := extractDoubleWord(d)
	if !ok {
		return d, time.Time{}, false
	}
	t = time.Unix(int64(tt), 0).In(time.UTC)
	ok = true
	return
}

func extractFixedData(d []byte, l int) (newPoint []byte, data []byte, ok bool) {
	if len(d) < l {
		return d, nil, false
	}
	return d[l:], d[0:l], true
}

func extractMPI(d []byte) (newPoint []byte, mpi *big.Int, ok bool) {
	d, mpiLen, ok := extractWord(d)
	if !ok || len(d) < int(mpiLen) {
		return nil, nil, false
	}

	mpi = new(big.Int).SetBytes(d[:int(mpiLen)])
	newPoint = d[int(mpiLen):]
	ok = true
	return
}
