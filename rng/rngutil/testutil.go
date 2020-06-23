package rngutil

import (
	"github.com/renproject/secp256k1-go"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/curve"

	"github.com/renproject/mpc/brng"
	"github.com/renproject/mpc/brng/brngutil"
	"github.com/renproject/mpc/open"
)

// Max returns the maximum of the two arguments
func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Min returns the minimum of the two arguments
func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetAllSharesAndCommitments computes BRNG shares and commitments for
// all players participating in the RNG protocol
func GetAllSharesAndCommitments(
	indices []open.Fn,
	b, k int,
	h curve.Point,
) (
	map[open.Fn][]shamir.VerifiableShares,
	map[open.Fn][][]shamir.Commitment,
) {
	setsOfSharesByPlayer := make(map[open.Fn][]shamir.VerifiableShares)
	setsOfCommitmentsByPlayer := make(map[open.Fn][][]shamir.Commitment)
	for _, index := range indices {
		setsOfSharesByPlayer[index] = make([]shamir.VerifiableShares, b)
		setsOfCommitmentsByPlayer[index] = make([][]shamir.Commitment, b)
	}

	brnger := brng.New(indices, h)
	for i := 0; i < b; i++ {
		table := brngutil.RandomValidTable(indices, h, k, k, len(indices))

		for _, index := range indices {
			slice := table.TakeSlice(index, indices)

			brnger.Reset()
			brnger.TransitionStart(k, k)
			shares, commitments, _ := brnger.TransitionSlice(slice)

			// Assign them to the `from` player
			setsOfSharesByPlayer[index][i] = shares
			setsOfCommitmentsByPlayer[index][i] = commitments
		}
	}

	return setsOfSharesByPlayer, setsOfCommitmentsByPlayer
}

// GetAllDirectedOpenings computes directed openings from all players
// to the single player in consideration
func GetAllDirectedOpenings(
	indices []open.Fn,
	to open.Fn,
	b, k int,
	h curve.Point,
) (
	map[open.Fn]shamir.VerifiableShares,
	map[open.Fn][]shamir.Commitment,
	[]shamir.VerifiableShares,
	[][]shamir.Commitment,
) {
	openingsByPlayer := make(map[open.Fn]shamir.VerifiableShares)
	commitmentsByPlayer := make(map[open.Fn][]shamir.Commitment)

	// Allocate memory for local variable
	setsOfSharesByPlayer := make(map[open.Fn][]shamir.VerifiableShares)
	setsOfCommitmentsByPlayer := make(map[open.Fn][][]shamir.Commitment)
	for _, from := range indices {
		openingsByPlayer[from] = make(shamir.VerifiableShares, b)
		commitmentsByPlayer[from] = make([]shamir.Commitment, b)
		setsOfSharesByPlayer[from] = make([]shamir.VerifiableShares, b)
		setsOfCommitmentsByPlayer[from] = make([][]shamir.Commitment, b)
	}

	// Generate random table and distribute appropriately
	brnger := brng.New(indices, h)
	for i := 0; i < b; i++ {
		table := brngutil.RandomValidTable(indices, h, k, k, len(indices))

		for _, from := range indices {
			// Take the appropriate slice from table
			slice := table.TakeSlice(from, indices)

			// Reset the dummy BRNG machine and extract shares/commitments
			brnger.Reset()
			brnger.TransitionStart(k, k)
			shares, commitments, _ := brnger.TransitionSlice(slice)

			// Assign them to the `from` player
			setsOfSharesByPlayer[from][i] = shares
			setsOfCommitmentsByPlayer[from][i] = commitments
		}
	}

	// Compute directed openings for each player
	for _, from := range indices {
		openings, commitments := GetDirectedOpenings(
			setsOfSharesByPlayer[from],
			setsOfCommitmentsByPlayer[from],
			to,
		)

		openingsByPlayer[from] = openings
		commitmentsByPlayer[from] = commitments
	}

	return openingsByPlayer,
		commitmentsByPlayer,
		setsOfSharesByPlayer[to],
		setsOfCommitmentsByPlayer[to]
}

// GetBrngOutputs uses a temporary BRNG engine to generate random
// sets of shares and commitments
func GetBrngOutputs(
	indices []open.Fn,
	index open.Fn,
	b, k int,
	h curve.Point,
) ([]shamir.VerifiableShares, [][]shamir.Commitment) {
	// We will need a BRNG engine
	brnger := brng.New(indices, h)

	// since we generate b unbiased random numbers together
	// and we need k BRNG calls for every random number generation
	setsOfShares := make([]shamir.VerifiableShares, b)
	setsOfCommitments := make([][]shamir.Commitment, b)
	for i := 0; i < b; i++ {
		// reset the BRNG engine
		brnger.Reset()
		_ = brnger.TransitionStart(k, k)

		// generate a valid table. Each table represents `k` BRNG runs
		// which also means, a batch size of `k` for the BRNG call
		table := brngutil.RandomValidTable(
			indices,      // indices of players
			h,            // pedersen commitment parameter
			k,            // reconstruction threshold
			k,            // batch size of each BRNG call
			len(indices), // height of the table
		)

		// get slice of this table for the player of our interest
		slice := table.TakeSlice(index, indices)

		// process slice to get shares and commitments
		shares, commitments, _ := brnger.TransitionSlice(slice)
		setsOfShares[i] = shares
		setsOfCommitments[i] = commitments
	}

	return setsOfShares, setsOfCommitments
}

// GetDirectedOpenings computes and returns openings and their
// respective commitments from a player for another player
// using the from player's sets of shares and commitments
func GetDirectedOpenings(
	setsOfShares []shamir.VerifiableShares,
	setsOfCommitments [][]shamir.Commitment,
	to open.Fn,
) (shamir.VerifiableShares, []shamir.Commitment) {
	computedShares := make(shamir.VerifiableShares, len(setsOfShares))
	computedCommitments := make([]shamir.Commitment, len(setsOfShares))

	for i, setOfShares := range setsOfShares {
		// Initialise the accumulators with the first values
		var accShare = setOfShares[0]
		var accCommitment shamir.Commitment
		accCommitment.Set(setsOfCommitments[i][0])
		var multiplier = secp256k1.OneSecp256k1N()

		// For all other shares and commitments
		for l := 1; l < len(setOfShares); l++ {
			multiplier.Mul(&multiplier, &to)
			multiplier.Normalize()

			var share = setOfShares[l]
			var commitment shamir.Commitment
			commitment.Set(setsOfCommitments[i][l])

			// Scale it by the multiplier
			share.Scale(&share, &multiplier)
			commitment.Scale(&commitment, &multiplier)

			// Add it to the accumulators
			accShare.Add(&accShare, &share)
			accCommitment.Add(&accCommitment, &commitment)
		}

		computedShares[i] = accShare
		computedCommitments[i].Set(accCommitment)
	}

	return computedShares, computedCommitments
}
