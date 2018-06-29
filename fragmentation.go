package prekeyserver

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type fragmentationContext struct {
	pieces []string
	have   []bool
	total  uint16
	count  uint16
}

type fragmentations struct {
	contexts map[uint32]*fragmentationContext
}

var fragmentationPrefix = "?OTRP|"

func newFragmentations() *fragmentations {
	return &fragmentations{
		contexts: make(map[uint32]*fragmentationContext),
	}
}

func isFragment(msg string) bool {
	return strings.HasPrefix(msg, fragmentationPrefix) && strings.HasSuffix(msg, ",")
}

func parseUint32(s string) (uint32, bool) {
	if res, e := strconv.ParseUint(s, 10, 32); e == nil {
		return uint32(res), true
	}
	return 0, false
}

func parseUint32Hex(s string) (uint32, bool) {
	if res, e := strconv.ParseUint(s, 16, 32); e == nil {
		return uint32(res), true
	}
	return 0, false
}

func parseUint16(s string) (uint16, bool) {
	if res, e := strconv.ParseUint(s, 10, 16); e == nil {
		return uint16(res), true
	}
	return 0, false
}

// newFragmentReceived receives a fragment, including the fragment prefix
// it will add the received information to the fragmentation context
// if the received fragment completes a message, it will be returned and the previous pieces will be removed
func (f *fragmentations) newFragmentReceived(frag string) (string, bool, error) {
	frag = frag[len(fragmentationPrefix) : len(frag)-1]
	fragOne := strings.SplitN(frag, "|", 3)
	if len(fragOne) < 3 {
		return "", false, errors.New("invalid fragmentation parse")
	}
	fragTwo := strings.SplitN(fragOne[2], ",", 4)
	if len(fragTwo) < 4 {
		return "", false, errors.New("invalid fragmentation parse")
	}

	id, ok1 := parseUint32(fragOne[0])
	_, ok2 := parseUint32Hex(fragOne[1])
	_, ok3 := parseUint32Hex(fragTwo[0])
	ix, ok4 := parseUint16(fragTwo[1])
	tot, ok5 := parseUint16(fragTwo[2])

	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ix > 0 && tot > 0 && ix <= tot) {
		return "", false, errors.New("invalid fragmentation parse")
	}

	fc, ok := f.contexts[id]
	if !ok {
		fc = newFragmentationContext(tot)
		f.contexts[id] = fc
	}

	if fc.total != tot {
		return "", false, errors.New("inconsistent total")
	}

	fc.add(ix, fragTwo[3])
	if fc.done() {
		complete := fc.complete()
		delete(f.contexts, id)
		return complete, true, nil
	} else {
		return "", false, nil
	}

}

func (f *fragmentations) cleanFragments() {
}

func newFragmentationContext(total uint16) *fragmentationContext {
	return &fragmentationContext{
		pieces: make([]string, total),
		have:   make([]bool, total),
		total:  total,
	}
}

func (fc *fragmentationContext) add(ix uint16, piece string) {
	if !fc.have[ix-1] {
		fc.have[ix-1] = true
		fc.pieces[ix-1] = piece
		fc.count++
	}
}

func (fc *fragmentationContext) done() bool {
	return fc.total == fc.count
}

func (fc *fragmentationContext) complete() string {
	return strings.Join(fc.pieces, "")
}

func generateRandomId(r WithRandom) uint32 {
	var dst [4]byte
	randomInto(r, dst[:])
	return binary.BigEndian.Uint32(dst[:])
}

func fragmentStart(i, fraglen int) int {
	return i * fraglen
}

func min(l, r int) int {
	if l < r {
		return l
	}
	return r
}

func fragmentEnd(i, fraglen, l int) int {
	return min((i+1)*fraglen, l)
}

func fragmentData(data string, i, fraglen, l int) string {
	return data[fragmentStart(i, fraglen):fragmentEnd(i, fraglen, l)]
}

func potentiallyFragment(msg string, fragLen int, r WithRandom) []string {
	l := len(msg)
	if fragLen == 0 || l <= fragLen {
		return []string{msg}
	}
	prefix := fmt.Sprintf("?OTRP|%d|BEEF|CADE,", generateRandomId(r))

	numFragments := (l / fragLen) + 1
	ret := make([]string, numFragments)
	for i := 0; i < numFragments; i++ {
		ret[i] = fmt.Sprintf("%s%d,%d,%s,", prefix, uint16(i+1), uint16(numFragments), fragmentData(msg, i, fragLen, l))
	}
	return ret
}

// TODO: we should make sure we don't mix up fragments from different users but with same ID
