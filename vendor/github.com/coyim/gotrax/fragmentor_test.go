package gotrax

import (
	"errors"
	"time"

	. "gopkg.in/check.v1"
)

func (s *GotraxSuite) Test_isFragment_returnsFalseForSomethingThatIsNotAFragment(c *C) {
	f := NewFragmentor("?OTRP|")
	c.Assert(f.IsFragment("Hello"), Equals, false)
	c.Assert(f.IsFragment("?OTRHello"), Equals, false)
	c.Assert(f.IsFragment("?OTRPHello"), Equals, false)
	c.Assert(f.IsFragment("A?OTRP|Hello,"), Equals, false)
	c.Assert(f.IsFragment("?OTRP|"), Equals, false)
}

func (s *GotraxSuite) Test_isFragment_returnsTrueForFragments(c *C) {
	f := NewFragmentor("?OTRP|")
	c.Assert(f.IsFragment("?OTRP|,"), Equals, true)
	c.Assert(f.IsFragment("?OTRP|hello world,"), Equals, true)
}

func (s *GotraxSuite) Test_newFragmentReceived_ReturnsTheFragmentIfItsASingleOne(c *C) {
	f := NewFragmentor("?OTRP|")
	r, complete, _ := f.NewFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,1,hello world,")
	c.Assert(r, Equals, "hello world")
	c.Assert(complete, Equals, true)
}

func (s *GotraxSuite) Test_Fragmentor_InstanceTagsFrom_returnsTheInstanceTags(c *C) {
	f := NewFragmentor("?OTRP|")
	is, ir, e := f.InstanceTagsFrom("?OTRP|45243|AF1FDEAD|BEEF,1,1,hello world,")
	c.Assert(e, IsNil)
	c.Assert(is, Equals, uint32(0xAF1FDEAD))
	c.Assert(ir, Equals, uint32(0x0000BEEF))
}

func (s *GotraxSuite) Test_Fragmentor_InstanceTagsFrom_WillFailOnShortParse(c *C) {
	f := NewFragmentor("?OTRP|")
	_, _, e := f.InstanceTagsFrom("?OTRP|45243")
	c.Assert(e, ErrorMatches, "invalid fragmentation parse")
}

func (s *GotraxSuite) Test_Fragmentor_InstanceTagsFrom_WillFailOnAnotherShortParse(c *C) {
	f := NewFragmentor("?OTRP|")
	_, _, e := f.InstanceTagsFrom("?OTRP|45243|AF1FDEAD|BEEF,1,")
	c.Assert(e, ErrorMatches, "invalid fragmentation parse")
}

func (s *GotraxSuite) Test_Fragmentor_InstanceTagsFrom_WillFailOnSenderInstanceTagParse(c *C) {
	f := NewFragmentor("?OTRP|")
	_, _, e := f.InstanceTagsFrom("?OTRP|45243|AF1FDEXD|BEEF,1,1,hello world,")
	c.Assert(e, ErrorMatches, "invalid fragmentation parse")
}

func (s *GotraxSuite) Test_Fragmentor_InstanceTagsFrom_WillFailOnReceiverInstanceTagParse(c *C) {
	f := NewFragmentor("?OTRP|")
	_, _, e := f.InstanceTagsFrom("?OTRP|45243|AF1FDED|XEEF,1,1,hello world,")
	c.Assert(e, ErrorMatches, "invalid fragmentation parse")
}

func (s *GotraxSuite) Test_newFragmentReceived_ReturnsTheFragmentIfItsASingleOneWithDifferentPrefix(c *C) {
	f := NewFragmentor("?OTRX|")
	r, complete, _ := f.NewFragmentReceived("me@example.org", "?OTRX|45243|AF1FDEAD|BEEF,1,1,hello world,")
	c.Assert(r, Equals, "hello world")
	c.Assert(complete, Equals, true)
}

func (s *GotraxSuite) Test_newFragmentReceived_ReturnsNothingWhenGivenTheFirstPiece(c *C) {
	f := NewFragmentor("?OTRP|")
	r, complete, _ := f.NewFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,2,hello,")
	c.Assert(r, Equals, "")
	c.Assert(complete, Equals, false)
}

func (s *GotraxSuite) Test_NewFragmentReceived_ReturnsTheFullMessageWhenBothPiecesArrived(c *C) {
	f := NewFragmentor("?OTRP|")
	f.NewFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,2,hello,")
	r, complete, _ := f.NewFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,2,2, world,")
	c.Assert(r, Equals, "hello world")
	c.Assert(complete, Equals, true)
}

func (s *GotraxSuite) Test_NewFragmentReceived_DoesntCareAboutOrderOfReceivedFragments(c *C) {
	f := NewFragmentor("?OTRP|")
	f.NewFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,2,2, world,")
	r, complete, e := f.NewFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,2,hello,")
	c.Assert(e, IsNil)
	c.Assert(r, Equals, "hello world")
	c.Assert(complete, Equals, true)
}

func (s *GotraxSuite) Test_NewFragmentReceived_IgnoresDuplicates(c *C) {
	f := NewFragmentor("?OTRP|")
	f.NewFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,2,hello,")
	f.NewFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,2,hello,")
	r, complete, _ := f.NewFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,2,2, world,")
	c.Assert(r, Equals, "hello world")
	c.Assert(complete, Equals, true)
}

func (s *GotraxSuite) Test_NewFragmentReceived_DoesntMixUpTwoDifferentIDs(c *C) {
	f := NewFragmentor("?OTRP|")
	_, co, _ := f.NewFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,2,hello,")
	c.Assert(co, Equals, false)

	_, co, _ = f.NewFragmentReceived("me@example.org", "?OTRP|45343|AF1FDEAD|BEEF,1,4,bla,")
	c.Assert(co, Equals, false)

	_, co, _ = f.NewFragmentReceived("me@example.org", "?OTRP|45343|AF1FDEAD|BEEF,3,4,foo,")
	c.Assert(co, Equals, false)

	_, co, _ = f.NewFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,2,2, wirl,")
	c.Assert(co, Equals, true)

	_, co, _ = f.NewFragmentReceived("me@example.org", "?OTRP|45343|AF1FDEAD|BEEF,2,4, hmm,")
	c.Assert(co, Equals, false)

	_, co, _ = f.NewFragmentReceived("me@example.org", "?OTRP|45343|AF1FDEAD|BEEF,4,4, haha,")
	c.Assert(co, Equals, true)
}

func (s *GotraxSuite) Test_NewFragmentReceived_StartsANewFragmentForTheSameIDAfterFinishingTheOld(c *C) {
	f := NewFragmentor("?OTRP|")
	f.NewFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,2,hello,")
	_, complete, _ := f.NewFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,2,2, world,")
	c.Assert(complete, Equals, true)

	_, co, _ := f.NewFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,2,hello,")
	c.Assert(co, Equals, false)
}

func (s *GotraxSuite) Test_NewFragmentReceived_ErrorsOnInvalidIndices(c *C) {
	f := NewFragmentor("?OTRP|")
	_, _, e := f.NewFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,0,2,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.NewFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,-42,2,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.NewFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,3,2,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))
}

func (s *GotraxSuite) Test_NewFragmentReceived_ErrorsOnInvalidTotals(c *C) {
	f := NewFragmentor("?OTRP|")
	_, _, e := f.NewFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,-2,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.NewFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,0,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))
}

func (s *GotraxSuite) Test_NewFragmentReceived_ErrorsOnInconsistentTotals(c *C) {
	f := NewFragmentor("?OTRP|")
	f.NewFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,3,hello,")
	_, _, e := f.NewFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,2,4,hello,")

	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("inconsistent total"))
}

func (s *GotraxSuite) Test_NewFragmentReceived_ErrorsOnImpossibleParsing(c *C) {
	f := NewFragmentor("?OTRP|")
	_, _, e := f.NewFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,2f,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.NewFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,f1,2,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.NewFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEFBEEFBEEF,1,2,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.NewFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEFS,1,2,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.NewFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEADB|BEEF,1,2,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.NewFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAS|BEEF,1,2,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.NewFragmentReceived("me@example.org", "?OTRP|-45243|AF1FDEAS|BEEF,1,2,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.NewFragmentReceived("me@example.org", "?OTRP|5A43|AF1FDEAS|BEEF,1,2,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.NewFragmentReceived("me@example.org", "?OTRP|5143|AF1FDEAS|BEEF,1,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.NewFragmentReceived("me@example.org", "?OTRP|5143|AF1FDEAS|BEEF,hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.NewFragmentReceived("me@example.org", "?OTRP|5143|AF1FDEAS|hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.NewFragmentReceived("me@example.org", "?OTRP|5143|hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))

	_, _, e = f.NewFragmentReceived("me@example.org", "?OTRP|hello,")
	c.Assert(e, Not(IsNil))
	c.Assert(e, DeepEquals, errors.New("invalid fragmentation parse"))
}

func (s *GotraxSuite) Test_potentiallyFragment_returnsTheStringWhenGivenALengthOfZero(c *C) {
	wr := FixedRandBytes([]byte{
		0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
	})
	f := NewFragmentor("?OTRP|")
	res := f.PotentiallyFragment("hello world", 0, 0xBEEF, 0xCADE, wr)
	c.Assert(res, DeepEquals, []string{"hello world"})
}

func (s *GotraxSuite) Test_potentiallyFragment_fragmentsCorrectly(c *C) {
	wr := FixedRandBytes([]byte{
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
	f := NewFragmentor("?OTRP|")
	res := f.PotentiallyFragment("hello world", 54, 0xBEEF, 0xCADE, wr)
	c.Assert(res, HasLen, 2)
	c.Assert(res[0], DeepEquals, "?OTRP|2880154539|0000BEEF|0000CADE,1,2,hello ,")
	c.Assert(res[1], DeepEquals, "?OTRP|2880154539|0000BEEF|0000CADE,2,2,world,")
}

func (s *GotraxSuite) Test_fragmentations_cleanup_removesOldContexts(c *C) {
	f := NewFragmentor("?OTRP|")
	f.NewFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,2,hello,")
	f.NewFragmentReceived("another@example.org", "?OTRP|12345|AF1FDEAD|BEEF,1,2,hello,")
	f.NewFragmentReceived("me@example.org", "?OTRP|45244|AF1FDEAD|BEEF,1,2,hello,")

	f.contexts["me@example.org/45243"].lastTouched = time.Now().Add(time.Duration(-11) * time.Minute)
	f.contexts["another@example.org/12345"].lastTouched = time.Now().Add(time.Duration(-7) * time.Minute)
	f.contexts["me@example.org/45244"].lastTouched = time.Now().Add(time.Duration(-4) * time.Minute)

	f.Cleanup(time.Duration(6) * time.Minute)

	c.Assert(f.contexts, HasLen, 1)
	c.Assert(f.contexts["me@example.org/45244"], Not(IsNil))
}

func (s *GotraxSuite) Test_fragmentations_NewFragmentReceived_willUpdateLastTouched(c *C) {
	f := NewFragmentor("?OTRP|")
	bef := time.Now()
	f.NewFragmentReceived("me@example.org", "?OTRP|45243|AF1FDEAD|BEEF,1,2,hello,")
	c.Assert(f.contexts["me@example.org/45243"].lastTouched.After(bef), Equals, true)
}
