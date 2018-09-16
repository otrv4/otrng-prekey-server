package prekeyserver

import (
	"github.com/coyim/gotrax"
	. "gopkg.in/check.v1"
)

func (s *GenericServerSuite) Test_generateEcdhProof_and_verify_generatesProofsThatValidates(c *C) {
	wr := gotrax.ReaderIntoWithRandom(gotrax.FixtureRand())
	values := make([]*gotrax.Keypair, 3)
	values[0] = gotrax.GenerateKeypair(wr)
	values[1] = gotrax.GenerateKeypair(wr)
	values[2] = gotrax.GenerateKeypair(wr)
	m := [64]byte{0x01, 0x02, 0x03}

	proof, e := generateEcdhProof(wr, values, m[:], usageProofMessageEcdh)
	c.Assert(e, IsNil)

	values2 := make([]*gotrax.PublicKey, 3)
	values2[0] = values[0].Pub
	values2[1] = values[1].Pub
	values2[2] = values[2].Pub

	c.Assert(proof.verify(values2, m[:], usageProofMessageEcdh), Equals, true)
	c.Assert(proof.verify(values2, m[:], usageProofSharedEcdh), Equals, false)

	m2 := [64]byte{0x02, 0x02, 0x03}
	c.Assert(proof.verify(values2, m2[:], usageProofMessageEcdh), Equals, false)
}
