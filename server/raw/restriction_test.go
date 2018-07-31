package main

import (
	. "gopkg.in/check.v1"
)

func (s *RawServerSuite) Test_contains_worksCorrectly(c *C) {
	c.Assert(contains(nil, "foo"), Equals, false)
	c.Assert(contains([]string{"one"}, "foo"), Equals, false)
	c.Assert(contains([]string{"one", "two"}, "foo"), Equals, false)
	c.Assert(contains([]string{"one", "two"}, "one"), Equals, true)
	c.Assert(contains([]string{"one", "two"}, "two"), Equals, true)
	c.Assert(contains([]string{"one", "two", "one"}, "one"), Equals, true)
}

func (s *RawServerSuite) Test_hasAnyPrefix_worksCorrectly(c *C) {
	c.Assert(hasAnyPrefix(nil, "foo"), Equals, false)
	c.Assert(hasAnyPrefix([]string{"one"}, "foo"), Equals, false)
	c.Assert(hasAnyPrefix([]string{"one", "two"}, "foo"), Equals, false)
	c.Assert(hasAnyPrefix([]string{"one", "two"}, "one"), Equals, true)
	c.Assert(hasAnyPrefix([]string{"one", "two"}, "two"), Equals, true)
	c.Assert(hasAnyPrefix([]string{"one", "two"}, "onefoo"), Equals, true)
	c.Assert(hasAnyPrefix([]string{"one", "two"}, "twobar"), Equals, true)
	c.Assert(hasAnyPrefix([]string{"one", "two", "one"}, "one"), Equals, true)
}

func (s *RawServerSuite) Test_hasAnySuffix_worksCorrectly(c *C) {
	c.Assert(hasAnySuffix(nil, "foo"), Equals, false)
	c.Assert(hasAnySuffix([]string{"one"}, "foo"), Equals, false)
	c.Assert(hasAnySuffix([]string{"one", "two"}, "foo"), Equals, false)
	c.Assert(hasAnySuffix([]string{"one", "two"}, "one"), Equals, true)
	c.Assert(hasAnySuffix([]string{"one", "two"}, "two"), Equals, true)
	c.Assert(hasAnySuffix([]string{"one", "two"}, "fooone"), Equals, true)
	c.Assert(hasAnySuffix([]string{"one", "two"}, "bartwo"), Equals, true)
	c.Assert(hasAnySuffix([]string{"one", "two", "one"}, "one"), Equals, true)
}

func (s *RawServerSuite) Test_separateRestrictions_givesAllGivenRestrictions(c *C) {
	*allowOnlyPrefix = ""
	*allowOnlySuffix = ""
	*allowOnly = ""
	a, b, cc := separateRestrictions()
	c.Assert(a, HasLen, 0)
	c.Assert(b, HasLen, 0)
	c.Assert(cc, HasLen, 0)

	*allowOnlyPrefix = "pref1,pref2"
	*allowOnlySuffix = "suff1,suff2"
	*allowOnly = "only1"
	a, b, cc = separateRestrictions()
	c.Assert(a, HasLen, 2)
	c.Assert(a, DeepEquals, []string{"pref1", "pref2"})
	c.Assert(b, HasLen, 2)
	c.Assert(b, DeepEquals, []string{"suff1", "suff2"})
	c.Assert(cc, HasLen, 1)
	c.Assert(cc, DeepEquals, []string{"only1"})
}

func (s *RawServerSuite) Test_commandLineRestrictor_returnsFalseIfNoRestrictionsGiven(c *C) {
	*allowOnlyPrefix = ""
	*allowOnlySuffix = ""
	*allowOnly = ""
	c.Assert(commandLineRestrictor("something"), Equals, false)
}

func (s *RawServerSuite) Test_commandLineRestrictor_restrictsOnPrefix(c *C) {
	*allowOnlyPrefix = "one"
	*allowOnlySuffix = ""
	*allowOnly = ""
	c.Assert(commandLineRestrictor("one"), Equals, false)
	c.Assert(commandLineRestrictor("onebla"), Equals, false)
	c.Assert(commandLineRestrictor("two"), Equals, true)
}

func (s *RawServerSuite) Test_commandLineRestrictor_restrictsOnSuffix(c *C) {
	*allowOnlyPrefix = ""
	*allowOnlySuffix = "two"
	*allowOnly = ""
	c.Assert(commandLineRestrictor("two"), Equals, false)
	c.Assert(commandLineRestrictor("footwo"), Equals, false)
	c.Assert(commandLineRestrictor("one"), Equals, true)
}

func (s *RawServerSuite) Test_commandLineRestrictor_restrictsOnOnly(c *C) {
	*allowOnlyPrefix = ""
	*allowOnlySuffix = ""
	*allowOnly = "one,two"
	c.Assert(commandLineRestrictor("one"), Equals, false)
	c.Assert(commandLineRestrictor("two"), Equals, false)
	c.Assert(commandLineRestrictor("onebar"), Equals, true)
}
