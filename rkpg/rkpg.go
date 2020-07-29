package rkpg

import (
	"fmt"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
)

type RKPGer struct {
	state  State
	points []secp256k1.Point
	params Params
}

func New(indices []secp256k1.Fn, h secp256k1.Point, rngShares, rzgShares shamir.VerifiableShares, rngComs []shamir.Commitment) (RKPGer, shamir.Shares, error) {
	n := len(indices)
	b := len(rngShares)
	if len(rngShares) != len(rzgShares) {
		return RKPGer{}, nil, fmt.Errorf(
			"rng and rzg shares have different batch sizes: expected %v (rng) to equal %v (rzg)",
			len(rngShares), len(rzgShares),
		)
	}
	if len(rngComs) != b {
		// TODO
	}
	k := rngComs[0].Len()
	params := CreateParams(k, b, h, indices)

	shares := make(shamir.Shares, len(rngShares))
	for i := range shares {
		rnShare := rngShares[i].Share()
		rzShare := rzgShares[i].Share()
		ind := rzShare.Index()
		if !rnShare.IndexEq(&ind) {
			return RKPGer{}, nil, fmt.Errorf("mismatched indices: expected %v to equal %v", rnShare.Index(), ind)
		}
		if _, ok := params.arrIndex[ind]; !ok {
			return RKPGer{}, nil, fmt.Errorf("indices out of range: index %v not in index set", ind)
		}

		dRnShare := shamir.NewShare(ind, rngShares[i].Decommitment())
		RzShare := rzgShares[i].Share()

		shares[i].Add(&dRnShare, &RzShare)
	}

	state := NewState(n, b)
	points := make([]secp256k1.Point, len(rngComs))
	for i := range points {
		points[i] = rngComs[i][0]
	}

	rkpger := RKPGer{state: state, points: points, params: params}

	return rkpger, shares, nil
}

// HandleShareBatch applies a state transition to the given state upon
// receiveing the given shares from another party during the open in the RKPG
// protocol. The given commitments correspond to the RNG shares that were input
// for RKPG. Once enough shares have been received to reconstruct, the
// commitments are used to compute and return the output public key batch. If
// not enough shares have been received, the return value will be nil.
func (rkpger *RKPGer) HandleShareBatch(shares shamir.Shares) (
	[]secp256k1.Point, TransitionEvent,
) {
	if len(shares) != int(rkpger.params.b) {
		return nil, WrongBatchSize
	}
	index := shares[0].Index()
	ind, ok := rkpger.params.arrIndex[index]
	if !ok {
		return nil, InvalidIndex
	}
	if rkpger.state.shareReceived[ind] {
		return nil, DuplicateIndex
	}
	// Check that all indices in the share batch are the same.
	for i := 1; i < len(shares); i++ {
		if !shares[i].IndexEq(&index) {
			return nil, InconsistentShares
		}
	}

	// Checks have passed so we update the rkpger.state.
	for i, buf := range rkpger.state.buffers {
		buf[ind] = shares[i].Value()
	}
	rkpger.state.shareReceived[ind] = true
	rkpger.state.count++

	if int(rkpger.state.count) < int(rkpger.params.n-rkpger.params.k+1) {
		// Not enough shares have been received for reconstruction.
		return nil, ShareAdded
	}
	secrets := make([]secp256k1.Fn, rkpger.params.b)
	for i, buf := range rkpger.state.buffers {
		poly, ok := rkpger.params.decoder.Decode(buf)
		if !ok {
			// The RS decoder was not able to reconstruct the polynomial
			// because there are too many incorrect shares.
			return nil, TooManyErrors
		}
		secrets[i] = *poly.Coefficient(0)
	}

	pubKeys := make([]secp256k1.Point, rkpger.params.b)
	for i, secret := range secrets {
		// Compute xG = (xG + sH) + (-s)H
		secret.Negate(&secret)
		pubKeys[i].Scale(&rkpger.params.h, &secret)
		pubKeys[i].Add(&pubKeys[i], &rkpger.points[i])
	}
	return pubKeys, Reconstructed
}
