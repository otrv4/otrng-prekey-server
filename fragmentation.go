package prekeyserver

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// This code will sometimes fragment messages in smaller
// pieces than necessary - this is to ensure that the header part
// fits. There exists an optimal algorithm for doing this, but honestly
// I don't think it's worth the trouble and complexity to implement it

type fragmentationContext struct {
	pieces      []string
	have        []bool
	total       uint16
	count       uint16
	lastTouched time.Time
}

type fragmentations struct {
	contexts map[string]*fragmentationContext
}

func newFragmentations() *fragmentations {
	return &fragmentations{
		contexts: make(map[string]*fragmentationContext),
	}
}

func (fc *fragmentationContext) hasExpired(timeout time.Duration) bool {
	return fc.lastTouched.Add(timeout).Before(time.Now())
}

func (f *fragmentations) cleanup(timeout time.Duration) {
	toRemove := []string{}
	for nm, fc := range f.contexts {
		if fc.hasExpired(timeout) {
			toRemove = append(toRemove, nm)
		}
	}
	for _, nm := range toRemove {
		delete(f.contexts, nm)
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
func (f *fragmentations) newFragmentReceived(from, frag string) (string, bool, error) {
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

	ctxID := fmt.Sprintf("%s/%d", from, id)
	fc, ok := f.contexts[ctxID]
	if !ok {
		fc = newFragmentationContext(tot)
		f.contexts[ctxID] = fc
	}

	if fc.total != tot {
		return "", false, errors.New("inconsistent total")
	}

	fc.add(ix, fragTwo[3])
	if fc.done() {
		complete := fc.complete()
		delete(f.contexts, ctxID)
		return complete, true, nil
	}
	return "", false, nil
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

func generateRandomID(r WithRandom) uint32 {
	var dst [4]byte
	randomInto(r, dst[:])
	return binary.BigEndian.Uint32(dst[:])
}

func fragmentStart(i, fraglen int) int {
	return i * (fraglen - totalEnvelopeLen)
}

func min(l, r int) int {
	if l < r {
		return l
	}
	return r
}

func fragmentEnd(i, fraglen, l int) int {
	return min((i+1)*(fraglen-totalEnvelopeLen), l)
}

func fragmentData(data string, i, fraglen, l int) string {
	return data[fragmentStart(i, fraglen):fragmentEnd(i, fraglen, l)]
}

//    ?OTRP + | + randomID + | + instanceTag + | + instanceTag + , + index + , + numFragments + ,
const maxPrefixLen = 4 + 1 + 10 + 1 + 8 + 1 + 8 + 1 + 5 + 1 + 5 + 1
const totalEnvelopeLen = maxPrefixLen + 1

func potentiallyFragment(msg string, fragLen int, r WithRandom) []string {
	l := len(msg)
	if fragLen == 0 || l+totalEnvelopeLen <= fragLen {
		return []string{msg}
	}
	prefix := fmt.Sprintf("?OTRP|%d|BEEF|CADE,", generateRandomID(r))
	numFragments := (l / (fragLen - totalEnvelopeLen)) + 1
	ret := make([]string, numFragments)
	for i := 0; i < numFragments; i++ {
		ret[i] = fmt.Sprintf("%s%d,%d,%s,", prefix, uint16(i+1), uint16(numFragments), fragmentData(msg, i, fragLen, l))
	}
	return ret
}
