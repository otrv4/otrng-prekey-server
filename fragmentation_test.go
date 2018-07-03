package prekeyserver

import (
	"errors"

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
