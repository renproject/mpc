package compute

import (
	"github.com/renproject/mpc/open"
	"github.com/renproject/shamir"

	"github.com/renproject/shamir/curve"
)

// OutputCommitment returns the commitment that corresponds to the output
// shares of RNG, given the input commitments from BRNG.
func OutputCommitment(coms []shamir.Commitment, isZero bool) shamir.Commitment {
	var commitment shamir.Commitment

	if isZero {
		commitment = shamir.NewCommitmentWithCapacity(len(coms) + 1)
		commitment.AppendPoint(curve.Infinity())
	} else {
		commitment = shamir.NewCommitmentWithCapacity(len(coms))
	}

	for _, c := range coms {
		commitment.AppendPoint(c.GetPoint(0))
	}

	return commitment
}

// ShareCommitment accepts the set of commitments and computes a weighted
// linear combination of those commitments. This accumulated value represents
// the commitment for the share of the final unbiased random number for the
// given index.
//
// Panics: This function panics if the length of the slice of commitments is
// less than 1.
func ShareCommitment(
	index open.Fn,
	coms []shamir.Commitment,
	isZero bool,
) shamir.Commitment {
	var acc shamir.Commitment

	acc.Set(coms[len(coms)-1])
	for l := len(coms) - 2; l >= 0; l-- {
		acc.Scale(&acc, &index)
		acc.Add(&acc, &coms[l])
	}

	if isZero {
		acc.Scale(&acc, &index)
	}

	return acc
}

// ShareOfShare accepts the set of verifiable shares and computes a weighted
// linear combination of those shares. Assuming that the input shares' secrets
// are coefficients of a polynomial, the output share is a share of this
// polynomial evaluated at the given index.
//
// Panics: This function panics if the length of the slice of commitments is
// less than 1.
func ShareOfShare(
	index open.Fn,
	vshares shamir.VerifiableShares,
	isZero bool,
) shamir.VerifiableShare {
	acc := vshares[len(vshares)-1]
	for l := len(vshares) - 2; l >= 0; l-- {
		acc.Scale(&acc, &index)
		acc.Add(&acc, &vshares[l])
	}

	if isZero {
		acc.Scale(&acc, &index)
	}

	return acc
}
