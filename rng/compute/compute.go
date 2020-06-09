package compute

import (
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
)

// ShareCommitment accepts the set of commitments and computes a weighted
// linear combination of those commitments. This accumulated value represents
// the commitment for the share of the final unbiased random number for the
// given index.
//
// Panics: This function panics if the length of the slice of commitments is
// less than 1.
func ShareCommitment(index secp256k1.Fn, coms []shamir.Commitment) shamir.Commitment {
	var acc shamir.Commitment

	acc.Set(coms[len(coms)-1])
	for l := len(coms) - 2; l >= 0; l-- {
		acc.Scale(acc, &index)
		acc.Add(acc, coms[l])
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
func ShareOfShare(index secp256k1.Fn, vshares shamir.VerifiableShares) shamir.VerifiableShare {
	acc := vshares[len(vshares)-1]
	for l := len(vshares) - 2; l >= 0; l-- {
		acc.Scale(&acc, &index)
		acc.Add(&acc, &vshares[l])
	}

	return acc
}

// Private functions
func initShareComputation(
	setOfShares shamir.VerifiableShares,
	toIndex open.Fn,
	isZero bool,
) (open.Fn, shamir.VerifiableShare) {
	var multiplier open.Fn
	var accShare shamir.VerifiableShare

	if isZero {
		multiplier.Set(&toIndex)
		accShare.Scale(&setOfShares[0], &multiplier)
	} else {
		multiplier = secp256k1.OneSecp256k1N()
		accShare = setOfShares[0]
	}

	return multiplier, accShare
}

func initCommitmentComputation(
	setOfCommitments []shamir.Commitment,
	toIndex open.Fn, isZero bool,
) (open.Fn, shamir.Commitment) {
	// Initialise the accumulators with the first values
	var multiplier open.Fn
	var accCommitment shamir.Commitment

	if isZero {
		multiplier.Set(&toIndex)
		accCommitment.Scale(&setOfCommitments[0], &multiplier)
	} else {
		multiplier = secp256k1.OneSecp256k1N()
		accCommitment.Set(setOfCommitments[0])
	}

	return multiplier, accCommitment
}
