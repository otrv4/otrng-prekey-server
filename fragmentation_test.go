package prekeyserver

import (
	"errors"
	"time"

	"github.com/coyim/gotrax"
	. "gopkg.in/check.v1"
)

func (s *GenericServerSuite) Test_isFragment_returnsFalseForSomethingThatIsNotAFragment(c *C) {
	c.Assert(isFragment("Hello"), Equals, false)
	c.Assert(isFragment("?OTRHello"), Equals, false)
	c.Assert(isFragment("?OTRPHello"), Equals, false)
	c.Assert(isFragment("A?OTRP|Hello,"), Equals, false)
	c.Assert(isFragment("?OTRP|"), Equals, false)
}

func (s *GenericServerSuite) Test_isFragment_returnsTrueForFragments(c *C) {
	c.Assert(isFragment("?OTRP|,"), Equals, true)
	c.Assert(isFragment("?OTRP|hello world,"), Equals, true)
}

func (s *GenericServerSuite) Test_newFragmentReceived_ReturnsTheFragmentIfItsASingleOne(c *C) {
	f := newFragmentations()
	r, complete, _ := f.newFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,1,hello world,")
	c.Assert(r, Equals, "hello world")
	c.Assert(complete, Equals, true)
}

func (s *GenericServerSuite) Test_newFragmentReceived_ReturnsNothingWhenGivenTheFirstPiece(c *C) {
	f := newFragmentations()
	r, complete, _ := f.newFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,2,hello,")
	c.Assert(r, Equals, "")
	c.Assert(complete, Equals, false)
}

func (s *GenericServerSuite) Test_newFragmentReceived_ReturnsTheFullMessageWhenBothPiecesArrived(c *C) {
	f := newFragmentations()
	f.newFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,2,hello,")
	r, complete, _ := f.newFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,2,2, world,")
	c.Assert(r, Equals, "hello world")
	c.Assert(complete, Equals, true)
}

func (s *GenericServerSuite) Test_newFragmentReceived_DoesntCareAboutOrderOfReceivedFragments(c *C) {
	f := newFragmentations()
	f.newFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,2,2, world,")
	r, complete, e := f.newFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,2,hello,")
	c.Assert(e, IsNil)
	c.Assert(r, Equals, "hello world")
	c.Assert(complete, Equals, true)
}

func (s *GenericServerSuite) Test_newFragmentReceived_IgnoresDuplicates(c *C) {
	f := newFragmentations()
	f.newFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,2,hello,")
	f.newFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,2,hello,")
	r, complete, _ := f.newFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,2,2, world,")
	c.Assert(r, Equals, "hello world")
	c.Assert(complete, Equals, true)
}

func (s *GenericServerSuite) Test_newFragmentReceived_DoesntMixUpTwoDifferentIDs(c *C) {
	f := newFragmentations()
	_, co, _ := f.newFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,2,hello,")
	c.Assert(co, Equals, false)

	_, co, _ = f.newFragmentReceived("me@example.org", "?OTRP|45343|AF1FDEAD|BEEF,1,4,bla,")
	c.Assert(co, Equals, false)

	_, co, _ = f.newFragmentReceived("me@example.org", "?OTRP|45343|AF1FDEAD|BEEF,3,4,foo,")
	c.Assert(co, Equals, false)

	_, co, _ = f.newFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,2,2, wirl,")
	c.Assert(co, Equals, true)

	_, co, _ = f.newFragmentReceived("me@example.org", "?OTRP|45343|AF1FDEAD|BEEF,2,4, hmm,")
	c.Assert(co, Equals, false)

	_, co, _ = f.newFragmentReceived("me@example.org", "?OTRP|45343|AF1FDEAD|BEEF,4,4, haha,")
	c.Assert(co, Equals, true)
}

func (s *GenericServerSuite) Test_newFragmentReceived_StartsANewFragmentForTheSameIDAfterFinishingTheOld(c *C) {
	f := newFragmentations()
	f.newFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,2,hello,")
	_, complete, _ := f.newFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,2,2, world,")
	c.Assert(complete, Equals, true)

	_, co, _ := f.newFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,2,hello,")
	c.Assert(co, Equals, false)
}

func (s *GenericServerSuite) Test_newFragmentReceived_ErrorsOnInvalidIndices(c *C) {
	f := newFragmentations()
	_, _, e := f.newFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,0,2,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.newFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,-42,2,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.newFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,3,2,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))
}

func (s *GenericServerSuite) Test_newFragmentReceived_ErrorsOnInvalidTotals(c *C) {
	f := newFragmentations()
	_, _, e := f.newFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,-2,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.newFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,0,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))
}

func (s *GenericServerSuite) Test_newFragmentReceived_ErrorsOnInconsistentTotals(c *C) {
	f := newFragmentations()
	f.newFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,3,hello,")
	_, _, e := f.newFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,2,4,hello,")

	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("inconsistent total"))
}

func (s *GenericServerSuite) Test_newFragmentReceived_ErrorsOnImpossibleParsing(c *C) {
	f := newFragmentations()
	_, _, e := f.newFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,2f,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.newFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,f1,2,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.newFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEFBEEFBEEF,1,2,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.newFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEFS,1,2,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.newFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEADB|BEEF,1,2,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.newFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAS|BEEF,1,2,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.newFragmentReceived("me@example.org", "?OTRP|-45243|AF1FDEAS|BEEF,1,2,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.newFragmentReceived("me@example.org", "?OTRP|5A43|AF1FDEAS|BEEF,1,2,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.newFragmentReceived("me@example.org", "?OTRP|5143|AF1FDEAS|BEEF,1,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.newFragmentReceived("me@example.org", "?OTRP|5143|AF1FDEAS|BEEF,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.newFragmentReceived("me@example.org", "?OTRP|5143|AF1FDEAS|hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.newFragmentReceived("me@example.org", "?OTRP|5143|hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.newFragmentReceived("me@example.org", "?OTRP|hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))
}

func (s *GenericServerSuite) Test_potentiallyFragment_fragmentsCorrectly(c *C) {
	wr := gotrax.FixedRandBytes([]byte{
		0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
		0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
		0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
		0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
		0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
		0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
		0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
		0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
		0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
		0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
	})
	res := potentiallyFragment("hello world", 54, wr)
	c.Assert(res, HasLen, 2)
	c.Assert(res[0], DeepEquals, "?OTRP|2880154539|BEEF|CADE,1,2,hello w,")
	c.Assert(res[1], DeepEquals, "?OTRP|2880154539|BEEF|CADE,2,2,orld,")
}

func (s *GenericServerSuite) Test_fragmentations_cleanup_removesOldContexts(c *C) {
	f := newFragmentations()
	f.newFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,2,hello,")
	f.newFragmentReceived("another@example.org", "?OTRP|12345|AF1FDEAD|BEEF,1,2,hello,")
	f.newFragmentReceived("me@example.org", "?OTRP|45244|AF1FDEAD|BEEF,1,2,hello,")

	f.contexts["me@example.org/45243"].lastTouched = time.Now().Add(time.Duration(-11) * time.Minute)
	f.contexts["another@example.org/12345"].lastTouched = time.Now().Add(time.Duration(-7) * time.Minute)
	f.contexts["me@example.org/45244"].lastTouched = time.Now().Add(time.Duration(-4) * time.Minute)

	f.cleanup(time.Duration(6) * time.Minute)

	c.Assert(f.contexts, HasLen, 1)
	c.Assert(f.contexts["me@example.org/45244"], Not(IsNil))
}

func (s *GenericServerSuite) Test_fragmentations_newFragmentReceived_willUpdateLastTouched(c *C) {
	f := newFragmentations()
	bef := time.Now()
	f.newFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,2,hello,")
	c.Assert(f.contexts["me@example.org/45243"].lastTouched.After(bef), Equals, true)
}
