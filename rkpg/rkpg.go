package rkpg

import (
	"fmt"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/rs"
)

type RKPGer struct {
	state State

	// Instance parameters
	k       int32
	points  []secp256k1.Point
	decoder rs.Decoder

	// Global parameters
	indices []secp256k1.Fn
	h       secp256k1.Point
}

func New(
	indices []secp256k1.Fn,
	h secp256k1.Point,
	rngShares, rzgShares shamir.VerifiableShares,
	rngComs []shamir.Commitment,
) (RKPGer, shamir.Shares, error) {
	n := len(indices)
	b := len(rngShares)
	if len(rzgShares) != b {
		panic(fmt.Sprintf(
			"rng and rzg shares have different batch sizes: expected %v (rng) to equal %v (rzg)",
			len(rngShares), len(rzgShares),
		))
	}
	if len(rngComs) != b {
		panic(fmt.Sprintf(
			"invalid commitment batch size: expected %v (rngShares), got %v",
			b, len(rngComs),
		))
	}
	k := rngComs[0].Len()

	shares := make(shamir.Shares, len(rngShares))
	for i := range shares {
		rzShare := rzgShares[i].Share()
		ind := rzShare.Index()
		dRnShare := shamir.NewShare(ind, rngShares[i].Decommitment())
		RzShare := rzgShares[i].Share()
		shares[i].Add(&dRnShare, &RzShare)
	}

	state := NewState(n, b)
	points := make([]secp256k1.Point, b)
	for i := range points {
		points[i] = rngComs[i][0]
	}
	indicesCopy := make([]secp256k1.Fn, n)
	copy(indicesCopy, indices)
	rkpger := RKPGer{
		state:   state,
		k:       int32(k),
		points:  points,
		decoder: rs.NewDecoder(indices, k),
		indices: indicesCopy,
		h:       h,
	}

	return rkpger, shares, nil
}

// HandleShareBatch applies a state transition to the given state upon
// receiveing the given shares from another party during the open in the RKPG
// protocol. Once enough shares have been received to reconstruct, the output
// public key batch is computed and returned. If not enough shares have been
// received, the return value will be nil.
func (rkpger *RKPGer) HandleShareBatch(shares shamir.Shares) (
	[]secp256k1.Point, error,
) {
	n := len(rkpger.indices)
	b := len(rkpger.points)
	if len(shares) != int(b) {
		return nil, ErrWrongBatchSize
	}
	// Check that the index of the first share is in the list of indices.
	ind := -1
	index := shares[0].Index()
	for i := range rkpger.indices {
		if index.Eq(&rkpger.indices[i]) {
			ind = i
		}
	}
	if ind < 0 {
		return nil, ErrInvalidIndex
	}

	if rkpger.state.shareReceived[ind] {
		return nil, ErrDuplicateIndex
	}
	// Check that all indices in the share batch are the same.
	for i := 1; i < len(shares); i++ {
		if !shares[i].IndexEq(&index) {
			return nil, ErrInconsistentShares
		}
	}

	// Checks have passed so we update the rkpger.state.
	for i, buf := range rkpger.state.buffers {
		buf[ind] = shares[i].Value()
	}
	rkpger.state.shareReceived[ind] = true
	rkpger.state.count++

	if int(rkpger.state.count) < n-int(rkpger.k)+1 {
		// Not enough shares have been received for reconstruction.
		return nil, nil
	}
	secrets := make([]secp256k1.Fn, b)
	for i, buf := range rkpger.state.buffers {
		poly, ok := rkpger.decoder.Decode(buf)
		if !ok {
			// The RS decoder was not able to reconstruct the polynomial
			// because there are too many incorrect shares.
			return nil, ErrTooManyErrors
		}
		secrets[i] = *poly.Coefficient(0)
	}

	pubKeys := make([]secp256k1.Point, b)
	for i, secret := range secrets {
		// Compute xG = (xG + sH) + (-s)H
		secret.Negate(&secret)
		pubKeys[i].Scale(&rkpger.h, &secret)
		pubKeys[i].Add(&pubKeys[i], &rkpger.points[i])
	}
	return pubKeys, nil
}
