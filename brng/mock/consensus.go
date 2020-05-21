package mock

import (
	"fmt"
	"io"
	"math/rand"

	"github.com/renproject/mpc/brng"
	"github.com/renproject/secp256k1-go"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/curve"
	"github.com/renproject/surge"
)

type PullConsensus struct {
	done         bool
	honestSubset []secp256k1.Secp256k1N
	threshold    int32
	table        brng.Table
	checker      shamir.VSSChecker
}

// SizeHint implements the surge.SizeHinter interface.
func (pc PullConsensus) SizeHint() int {
	return surge.SizeHint(pc.done) +
		surge.SizeHint(pc.honestSubset) +
		surge.SizeHint(pc.threshold) +
		pc.table.SizeHint() +
		pc.checker.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (pc PullConsensus) Marshal(w io.Writer, m int) (int, error) {
	m, err := surge.Marshal(w, pc.done, m)
	if err != nil {
		return m, fmt.Errorf("error marshaling done: %v", err)
	}
	m, err = surge.Marshal(w, pc.honestSubset, m)
	if err != nil {
		return m, fmt.Errorf("error marshaling honestSubset: %v", err)
	}
	m, err = surge.Marshal(w, pc.threshold, m)
	if err != nil {
		return m, fmt.Errorf("error marshaling threshold: %v", err)
	}
	m, err = pc.table.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("error marshaling table: %v", err)
	}
	m, err = pc.checker.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("error marshaling checker: %v", err)
	}
	return m, nil
}

// Unmarshal implements the surge.Unmarshaler interface.
func (pc PullConsensus) Unmarshal(r io.Reader, m int) (int, error) {
	m, err := surge.Unmarshal(r, pc.done, m)
	if err != nil {
		return m, fmt.Errorf("error unmarshaling done: %v", err)
	}
	m, err = surge.Unmarshal(r, pc.honestSubset, m)
	if err != nil {
		return m, fmt.Errorf("error unmarshaling honestSubset: %v", err)
	}
	m, err = surge.Unmarshal(r, pc.threshold, m)
	if err != nil {
		return m, fmt.Errorf("error unmarshaling threshold: %v", err)
	}
	m, err = pc.table.Unmarshal(r, m)
	if err != nil {
		return m, fmt.Errorf("error unmarshaling table: %v", err)
	}
	m, err = pc.checker.Unmarshal(r, m)
	if err != nil {
		return m, fmt.Errorf("error unmarshaling checker: %v", err)
	}
	return m, nil
}

func NewPullConsensus(honestIndices []secp256k1.Secp256k1N, advCount int, h curve.Point) PullConsensus {
	var table brng.Table

	done := false
	threshold := int32(advCount) + 1
	checker := shamir.NewVSSChecker(h)

	// Pick a random subset of honest parties that we will require to agree in
	// consensus.
	honestSubset := make([]secp256k1.Secp256k1N, len(honestIndices))
	copy(honestSubset, honestIndices)
	rand.Shuffle(len(honestSubset), func(i, j int) {
		honestSubset[i], honestSubset[j] = honestSubset[j], honestSubset[i]
	})
	honestSubset = honestSubset[:advCount+1]

	return PullConsensus{
		done,
		honestSubset,
		threshold,
		table,
		checker,
	}
}

// Table returns the output table of the consensus algorithm. This table will
// only be correct if `HandleRow` has returned `true`.
func (pc PullConsensus) Table() brng.Table {
	return pc.table
}

// HandleRow processes a row received from a player. It returns true if
// consensus has completed, at which point the complete output table can be
// accessed, and false otherwise.
func (pc *PullConsensus) HandleRow(row brng.Row) bool {
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
			if !pc.checker.IsValid(&c, &share) {
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
