package prekeyserver

import (
	"math/big"

	. "gopkg.in/check.v1"
)

func (s *GenericServerSuite) Test_validateDHValue_validatesAValidValue(c *C) {
	c.Assert(validateDHValue(g3.Bytes()), IsNil)
}

func (s *GenericServerSuite) Test_validateDHValue_checksAValueLessThanG3(c *C) {
	c.Assert(validateDHValue([]byte{0x01}), ErrorMatches, "value less than g3")
}

func (s *GenericServerSuite) Test_validateDHValue_checksAValueLargerThanDHPMinusTwo(c *C) {
	t := new(big.Int).Sub(dhP, big.NewInt(1))
	c.Assert(validateDHValue(t.Bytes()), ErrorMatches, "value larger than group")
}

func (s *GenericServerSuite) Test_validateDHValue_findNonGroupMember(c *C) {
	t := big.NewInt(5)
	c.Assert(validateDHValue(t.Bytes()), ErrorMatches, "value is not part of group")
}
