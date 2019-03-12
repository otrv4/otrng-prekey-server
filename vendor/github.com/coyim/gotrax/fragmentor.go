package gotrax

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// This code will sometimes fragment messages in smaller
// pieces than necessary - this is to ensure that the header part
// fits. There exists an optimal algorithm for doing this, but honestly
// I don't think it's worth the trouble and complexity to implement it

// Fragmentor contains all the functionality for keeping track of fragmentation or de-fragmentation
type Fragmentor struct {
	contexts map[string]*fragmentationContext
	// For now we will have one big mutex for all contexts
	// This should be fine for large amounts of traffic
	// since each fragmentation process is very very fast
	sync.Mutex

	prefix string
}

type fragmentationContext struct {
	pieces      []string
	have        []bool
	total       uint16
	count       uint16
	lastTouched time.Time
}

// NewFragmentor creates a new Fragmentor
func NewFragmentor(prefix string) *Fragmentor {
	return &Fragmentor{
		contexts: make(map[string]*fragmentationContext),
		prefix:   prefix,
	}
}

func (fc *fragmentationContext) hasExpired(timeout time.Duration) bool {
	return fc.lastTouched.Add(timeout).Before(time.Now())
}

// Cleanup should be periodically called to remove all old contexts
func (f *Fragmentor) Cleanup(timeout time.Duration) {
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

// IsFragment checks whether the given message is a fragment
func (f *Fragmentor) IsFragment(msg string) bool {
	return strings.HasPrefix(msg, f.prefix) && strings.HasSuffix(msg, ",")
}

func parseUint16(s string) (uint16, bool) {
	if res, e := strconv.ParseUint(s, 10, 16); e == nil {
		return uint16(res), true
	}
	return 0, false
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

func (f *Fragmentor) getOrCreate(ctx string, tot uint16) *fragmentationContext {
	fc, ok := f.contexts[ctx]
	if !ok {
		fc = newFragmentationContext(tot)
		f.contexts[ctx] = fc
	}
	return fc
}

// InstanceTagsFrom tries to extract the instance tags from the prefix of the given fragmented string
func (f *Fragmentor) InstanceTagsFrom(frag string) (uint32, uint32, error) {
	frag = frag[len(f.prefix) : len(frag)-1]
	fragOne := strings.SplitN(frag, "|", 3)
	if len(fragOne) < 3 {
		return 0, 0, errors.New("invalid fragmentation parse")
	}
	fragTwo := strings.SplitN(fragOne[2], ",", 4)
	if len(fragTwo) < 4 {
		return 0, 0, errors.New("invalid fragmentation parse")
	}

	itagS, ok1 := parseUint32Hex(fragOne[1])
	itagR, ok2 := parseUint32Hex(fragTwo[0])

	if !(ok1 && ok2) {
		return 0, 0, errors.New("invalid fragmentation parse")
	}

	return itagS, itagR, nil
}

// NewFragmentReceived receives a fragment, including the fragment prefix
// it will add the received information to the fragmentation context
// if the received fragment completes a message, it will be returned and the previous pieces will be removed
func (f *Fragmentor) NewFragmentReceived(from, frag string) (string, bool, error) {
	frag = frag[len(f.prefix) : len(frag)-1]
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
	f.Lock()
	defer f.Unlock()
	fc := f.getOrCreate(ctxID, tot)

	if fc.total != tot {
		return "", false, errors.New("inconsistent total")
	}

	fc.lastTouched = time.Now()

	fc.add(ix, fragTwo[3])
	if fc.done() {
		complete := fc.complete()
		delete(f.contexts, ctxID)
		return complete, true, nil
	}
	return "", false, nil
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
	RandomInto(r, dst[:])
	return binary.BigEndian.Uint32(dst[:])
}

func min(l, r int) int {
	if l < r {
		return l
	}
	return r
}

func (f *Fragmentor) fragmentStart(i, fraglen int) int {
	return i * (fraglen - (len(f.prefix) + totalEnvelopeLen))
}

func (f *Fragmentor) fragmentEnd(i, fraglen, l int) int {
	return min((i+1)*(fraglen-(len(f.prefix)+totalEnvelopeLen)), l)
}

func (f *Fragmentor) fragmentData(data string, i, fraglen, l int) string {
	return data[f.fragmentStart(i, fraglen):f.fragmentEnd(i, fraglen, l)]
}

//    randomID + | + instanceTag + | + instanceTag + , + index + , + numFragments + ,
const maxPrefixLen = 10 + 1 + 8 + 1 + 8 + 1 + 5 + 1 + 5 + 1
const totalEnvelopeLen = maxPrefixLen + 1

// PotentiallyFragment checks whether it should fragment the given message, and if so does it
func (f *Fragmentor) PotentiallyFragment(msg string, fragLen int, itagS, itagR uint32, r WithRandom) []string {
	l := len(msg)

	if fragLen == 0 || l+len(f.prefix)+totalEnvelopeLen <= fragLen {
		return []string{msg}
	}
	prefix := fmt.Sprintf("%s%d|%08X|%08X,", f.prefix, generateRandomID(r), itagS, itagR)
	numFragments := (l / (fragLen - (len(f.prefix) + totalEnvelopeLen))) + 1
	ret := make([]string, numFragments)
	for i := 0; i < numFragments; i++ {
		ret[i] = fmt.Sprintf("%s%d,%d,%s,", prefix, uint16(i+1), uint16(numFragments), f.fragmentData(msg, i, fragLen, l))
	}
	return ret
}
