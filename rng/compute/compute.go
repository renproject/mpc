package compute

import (
	"github.com/renproject/mpc/open"
	"github.com/renproject/secp256k1-go"
	"github.com/renproject/shamir"
)

// OutputCommitment returns the commitment that corresponds to the output
// shares of RNG, given the input commitments from BRNG.
func OutputCommitment(coms []shamir.Commitment) shamir.Commitment {
	commitment := shamir.NewCommitmentWithCapacity(len(coms))

	for _, c := range coms {
		commitment.AppendPoint(c.GetPoint(0))
	}

	return commitment
}

// ShareCommitment accepts the set of commitments and computes a weighted
// linear combination of those commitments. This accumulated value represents
// the commitment for the share of the final unbiased random number for the
// given index.
func ShareCommitment(
	index open.Fn,
	coms []shamir.Commitment,
) shamir.Commitment {
	// Initialise the accumulators with the first values.
	var multiplier open.Fn
	var acc, term shamir.Commitment

	multiplier = secp256k1.OneSecp256k1N()
	acc.Set(coms[0])
	term = shamir.NewCommitmentWithCapacity(acc.Len())

	// For all other commitments,
	for l := 1; l < len(coms); l++ {
		// set the multiplier to index^l,
		multiplier.Mul(&multiplier, &index)
		multiplier.Normalize()

		// scale by the multiplier and add to the accumulator.
		term.Scale(&coms[l], &multiplier)
		acc.Add(&acc, &term)
	}

	return acc
}

// ShareOfShare accepts the set of verifiable shares and computes a weighted
// linear combination of those shares. Assuming that the input shares' secrets
// are coefficients of a polynomial, the output share is a share of this
// polynomial evaluated at the given index.
func ShareOfShare(
	index open.Fn,
	vshares shamir.VerifiableShares,
) shamir.VerifiableShare {
	// Initialise the accumulators with the first values.
	var multiplier open.Fn
	var acc, term shamir.VerifiableShare

	multiplier = secp256k1.OneSecp256k1N()
	acc = vshares[0]

	// For all other shares,
	for l := 1; l < len(vshares); l++ {
		// scale the multiplier,
		multiplier.Mul(&multiplier, &index)
		multiplier.Normalize()

		// scale by the multiplier and add to the accumulator.
		term.Scale(&vshares[l], &multiplier)
		acc.Add(&acc, &term)
	}

	return acc
}
