package mock

import (
	"fmt"
	"math/rand"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/surge"

	"github.com/renproject/mpc/brng/table"
)

// PullConsensus represents an ideal trusted party for achieving consensus on a
// table of shares to be used during the BRNG protocol.
type PullConsensus struct {
	done         bool
	indices      []secp256k1.Fn
	honestSubset []secp256k1.Fn
	threshold    int32
	table        table.Table
	h            secp256k1.Point
}

// SizeHint implements the surge.SizeHinter interface.
func (pc PullConsensus) SizeHint() int {
	return surge.SizeHint(pc.done) +
		surge.SizeHint(pc.indices) +
		surge.SizeHint(pc.honestSubset) +
		surge.SizeHint(pc.threshold) +
		pc.table.SizeHint() +
		pc.h.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (pc PullConsensus) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := surge.MarshalBool(pc.done, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("error marshaling done: %v", err)
	}
	buf, rem, err = surge.Marshal(pc.indices, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("error marshaling indices: %v", err)
	}
	buf, rem, err = surge.Marshal(pc.honestSubset, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("error marshaling honestSubset: %v", err)
	}
	buf, rem, err = surge.MarshalI32(pc.threshold, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("error marshaling threshold: %v", err)
	}
	buf, rem, err = pc.table.Marshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("error marshaling table: %v", err)
	}
	buf, rem, err = pc.h.Marshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("error marshaling h: %v", err)
	}
	return buf, rem, nil
}

// Unmarshal implements the surge.Unmarshaler interface.
func (pc PullConsensus) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := surge.UnmarshalBool(&pc.done, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("error unmarshaling done: %v", err)
	}
	buf, rem, err = surge.Unmarshal(&pc.indices, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("error unmarshaling indices: %v", err)
	}
	buf, rem, err = surge.Unmarshal(&pc.honestSubset, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("error unmarshaling honestSubset: %v", err)
	}
	buf, rem, err = surge.UnmarshalI32(&pc.threshold, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("error unmarshaling threshold: %v", err)
	}
	buf, rem, err = pc.table.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("error unmarshaling table: %v", err)
	}
	buf, rem, err = pc.h.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("error unmarshaling h: %v", err)
	}
	return buf, rem, nil
}

// NewPullConsensus constructs a new mock consensus object. The honest indices
// represent the indices of the honest players and the adversary count
// represents the maximum number of adversaries that there will be. `h`
// represents the Pedersen commitment parameter.
func NewPullConsensus(inds, honestIndices []secp256k1.Fn, advCount int, h secp256k1.Point) PullConsensus {
	var table table.Table

	done := false
	threshold := int32(advCount) + 1
	indices := make([]secp256k1.Fn, len(inds))
	copy(indices, inds)

	// Pick a random subset of honest parties that we will require to agree in
	// consensus.
	honestSubset := make([]secp256k1.Fn, len(honestIndices))
	copy(honestSubset, honestIndices)
	rand.Shuffle(len(honestSubset), func(i, j int) {
		honestSubset[i], honestSubset[j] = honestSubset[j], honestSubset[i]
	})
	honestSubset = honestSubset[:advCount+1]

	return PullConsensus{
		done,
		indices,
		honestSubset,
		threshold,
		table,
		h,
	}
}

// Table returns the output table of the consensus algorithm. This table will
// only be correct if `HandleRow` has returned `true`.
func (pc PullConsensus) Table() table.Table {
	return pc.table
}

// Done returns if the consensus engine has already reached consensus or not
// yet.
func (pc PullConsensus) Done() bool {
	return pc.done
}

// TakeSlice returns the appropriate slice of the assembled table, at
// index
func (pc PullConsensus) TakeSlice(index secp256k1.Fn) table.Slice {
	return pc.table.TakeSlice(index, pc.indices)
}

// HandleRow processes a row received from a player. It returns true if
// consensus has completed, at which point the complete output table can be
// accessed, and false otherwise.
func (pc *PullConsensus) HandleRow(row table.Row) bool {
	if pc.done {
		return true
	}

	for _, sharing := range row {
		for _, index := range pc.honestSubset {
			share, err := sharing.ShareWithIndex(index)
			if err != nil {
				panic("row should contain all honest indices")
			}

			c := sharing.Commitment()
			if !shamir.IsValid(pc.h, &c, &share) {
				return pc.done
			}
		}
	}

	pc.table = append(pc.table, row)
	if len(pc.table) == int(pc.threshold) {
		pc.done = true
	}

	return pc.done
}
