package rngutil

import (
	"math/rand"

	"github.com/renproject/mpc/open"
	"github.com/renproject/mpc/rng/compute"
	"github.com/renproject/secp256k1-go"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/curve"
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

// RandomOtherIndex returns a random index from the list of given indices that
// is not equal to the given index.
func RandomOtherIndex(indices []open.Fn, avoid *open.Fn) open.Fn {
	index := indices[rand.Intn(len(indices))]
	for index.Eq(avoid) {
		index = indices[rand.Intn(len(indices))]
	}
	return index
}

// BRNGOutputBatch creates a random output for one player from BRNG, with the
// given batch number.
func BRNGOutputBatch(index open.Fn, b, k int, h curve.Point) (
	[]shamir.VerifiableShares,
	[][]shamir.Commitment,
) {
	shares := make([]shamir.VerifiableShares, b)
	coms := make([][]shamir.Commitment, b)

	for i := 0; i < b; i++ {
		shares[i], coms[i] = BRNGOutput(index, k, h)
	}

	return shares, coms
}

// BRNGOutput creates a random output for one player from BRNG.
func BRNGOutput(index open.Fn, k int, h curve.Point) (
	shamir.VerifiableShares,
	[]shamir.Commitment,
) {
	shares := make(shamir.VerifiableShares, k)
	coms := make([]shamir.Commitment, k)

	var bs [32]byte
	gPow := curve.New()
	hPow := curve.New()
	sCoeffs := make([]open.Fn, k)
	rCoeffs := make([]open.Fn, k)
	for i := 0; i < k; i++ {
		for j := 0; j < k; j++ {
			sCoeffs[j] = secp256k1.RandomSecp256k1N()
			rCoeffs[j] = secp256k1.RandomSecp256k1N()

			sCoeffs[j].GetB32(bs[:])
			gPow.BaseExp(bs)
			rCoeffs[j].GetB32(bs[:])
			hPow.Scale(&h, bs)
			gPow.Add(&gPow, &hPow)
			coms[i].AppendPoint(gPow)
		}

		shares[i] = shamir.NewVerifiableShare(shamir.NewShare(index, sCoeffs[k-1]), rCoeffs[k-1])
		for j := k - 2; j >= 0; j-- {
			share := shamir.NewVerifiableShare(shamir.NewShare(index, sCoeffs[j]), rCoeffs[j])
			shares[i].Scale(&shares[i], &index)
			shares[i].Add(&shares[i], &share)
		}
	}

	return shares, coms
}

// BRNGOutputFullBatch creates a random output of BRNG for all players with the
// given batch size. The returned map of shares is indexed by the index of the
// player, and the returned commitments are the same for all players.
func BRNGOutputFullBatch(
	indices []open.Fn,
	b, c, k int,
	h curve.Point,
) (
	map[open.Fn][]shamir.VerifiableShares,
	[][]shamir.Commitment,
) {
	n := len(indices)

	shares := make(map[open.Fn][]shamir.VerifiableShares, n)
	coms := make([][]shamir.Commitment, b)

	var shareBatch []shamir.VerifiableShares
	for i := 0; i < b; i++ {
		shareBatch, coms[i] = BRNGOutputFull(indices, c, k, h)

		for j, ind := range indices {
			shares[ind] = append(shares[ind], shareBatch[j])
		}
	}

	return shares, coms
}

// BRNGOutputFull creates a random output of BRNG for all players.
func BRNGOutputFull(
	indices []open.Fn,
	c, k int,
	h curve.Point,
) (
	[]shamir.VerifiableShares,
	[]shamir.Commitment,
) {
	n := len(indices)

	sharer := shamir.NewVSSharer(indices, h)
	coefShares := make([]shamir.VerifiableShares, c)
	coefComms := make([]shamir.Commitment, c)

	for i := range coefShares {
		coefShares[i] = make(shamir.VerifiableShares, n)
		coefComms[i] = shamir.NewCommitmentWithCapacity(k)
		sharer.Share(&coefShares[i], &coefComms[i], secp256k1.RandomSecp256k1N(), k)
	}

	coefSharesTrans := make([]shamir.VerifiableShares, n)
	for i := range coefSharesTrans {
		coefSharesTrans[i] = make(shamir.VerifiableShares, c)
	}

	for i, sharing := range coefShares {
		for j, share := range sharing {
			coefSharesTrans[j][i] = share
		}
	}

	return coefSharesTrans, coefComms
}

// RNGSharesBatch creates random valid inputs for the RNG state machine for the
// given batch size. The first two return values are the outputs from BRNG, and
// the last two return values are the shares from the other players that the
// player corresponding to `index` is expecting.
func RNGSharesBatch(
	indices []open.Fn,
	index open.Fn,
	b, k int,
	h curve.Point,
	isZero bool,
) (
	[]shamir.VerifiableShares,
	[][]shamir.Commitment,
	map[open.Fn]shamir.VerifiableShares,
	[]shamir.Commitment,
) {
	n := len(indices)
	brngComs := make([][]shamir.Commitment, b)
	brngShares := make([]shamir.VerifiableShares, b)
	coms := make([]shamir.Commitment, b)
	shares := make(map[open.Fn]shamir.VerifiableShares, n)
	for _, ind := range indices {
		shares[ind] = make(shamir.VerifiableShares, b)
	}

	var rngShares shamir.VerifiableShares
	for i := 0; i < b; i++ {
		brngShares[i], brngComs[i], rngShares, coms[i] = RNGShares(indices, index, k, h, isZero)

		for j, share := range rngShares {
			shares[indices[j]][i] = share
		}
	}

	return brngShares, brngComs, shares, coms
}

// RNGShares creates random valid inputs for the RNG state machine. The first
// two return values are the outputs from BRNG, and the last two return values
// are the shares from the other players that the player corresponding to
// `index` is expecting.
func RNGShares(
	indices []open.Fn,
	index open.Fn,
	k int,
	h curve.Point,
	isZero bool,
) (shamir.VerifiableShares, []shamir.Commitment, shamir.VerifiableShares, shamir.Commitment) {
	n := len(indices)
	var coefSharesTrans []shamir.VerifiableShares
	var coefComms []shamir.Commitment
	if isZero {
		coefSharesTrans, coefComms = BRNGOutputFull(indices, k-1, k, h)
	} else {
		coefSharesTrans, coefComms = BRNGOutputFull(indices, k, k, h)
	}

	com := compute.ShareCommitment(index, coefComms, isZero)

	shares := make(shamir.VerifiableShares, n)
	for i := range shares {
		shares[i] = compute.ShareOfShare(index, coefSharesTrans[i], isZero)
	}

	var ind int
	for i := range indices {
		if indices[i].Eq(&index) {
			ind = i
		}
	}

	return coefSharesTrans[ind], coefComms, shares, com
}
