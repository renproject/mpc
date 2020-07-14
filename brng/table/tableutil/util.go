package tableutil

import (
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"

	"github.com/renproject/mpc/brng/table"
)

func RandomValidElement(
	to, from secp256k1.Fn, h secp256k1.Point,
) (table.Element, shamir.VerifiableShare, shamir.Commitment) {
	indices := []secp256k1.Fn{to}
	shares := make(shamir.VerifiableShares, 1)
	commitment := shamir.NewCommitmentWithCapacity(1)
	vssharer := shamir.NewVSSharer(indices, h)
	vssharer.Share(&shares, &commitment, secp256k1.RandomSecp256k1N(), 1)

	var c shamir.Commitment
	c.Set(commitment)

	return table.NewElement(from, shares[0], commitment), shares[0], c
}

func RandomValidCol(
	to secp256k1.Fn, indices []secp256k1.Fn, h secp256k1.Point,
) (table.Col, shamir.VerifiableShare, shamir.Commitment) {
	col := make(table.Col, len(indices))

	element, sumShares, sumCommitments := RandomValidElement(to, indices[0], h)
	col[0] = element

	for i := 1; i < len(indices); i++ {
		element, share, commitment := RandomValidElement(to, indices[i], h)

		col[i] = element
		sumShares.Add(&sumShares, &share)
		sumCommitments.Add(sumCommitments, commitment)
	}

	return col, sumShares, sumCommitments
}
