package prekeyserver

import (
	"math/big"

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

func randomDhSecretValue(wr gotrax.WithRandom) *big.Int {
	buf := make([]byte, 80)
	gotrax.RandomInto(wr, buf)
	return new(big.Int).SetBytes(buf)
}

func (s *GenericServerSuite) Test_generateDhProof_and_verify_generatesProofsThatValidates(c *C) {
	wr := gotrax.ReaderIntoWithRandom(gotrax.FixtureRand())
	valuesPriv := make([]*big.Int, 3)
	valuesPriv[0] = randomDhSecretValue(wr)
	valuesPriv[1] = randomDhSecretValue(wr)
	valuesPriv[2] = randomDhSecretValue(wr)

	valuesPub := make([]*big.Int, 3)
	valuesPub[0] = new(big.Int).Exp(g3, valuesPriv[0], dhP)
	valuesPub[1] = new(big.Int).Exp(g3, valuesPriv[1], dhP)
	valuesPub[2] = new(big.Int).Exp(g3, valuesPriv[2], dhP)

	m := [64]byte{0x01, 0x02, 0x03}

	proof, e := generateDhProof(wr, valuesPriv, valuesPub, m[:], usageProofMessageDh)
	c.Assert(e, IsNil)

	c.Assert(proof.verify(valuesPub, m[:], usageProofMessageDh), Equals, true)
	c.Assert(proof.verify(valuesPub, m[:], usageProofSharedEcdh), Equals, false)

	m2 := [64]byte{0x02, 0x02, 0x03}
	c.Assert(proof.verify(valuesPub, m2[:], usageProofMessageDh), Equals, false)
}
