package brng

import (
	"fmt"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"

	"github.com/renproject/mpc/brng/table"
)

type BRNGer struct {
	batchSize uint32
	h         secp256k1.Point
}

// New creates a new BRNG state machine for the given indices and pedersen
// parameter h.
func New(batchSize, k uint32, indices []secp256k1.Fn, h secp256k1.Point) (BRNGer, table.Row) {
	row := table.MakeRow(len(indices), int(k), int(batchSize))
	for i := range row {
		r := secp256k1.RandomFn()
		pointerToShares := row[i].BorrowShares()
		pointerToCommitment := row[i].BorrowCommitment()
		shamir.VShareSecret(pointerToShares, pointerToCommitment, indices, h, r, int(k))
	}
	brnger := BRNGer{batchSize, h}
	return brnger, row
}

// HandleSlice performs the state transition for the BRNger state machine upon
// receiving a slice.
func (brnger *BRNGer) HandleSlice(slice table.Slice) (
	shamir.VerifiableShares, []shamir.Commitment, []table.Element,
) {
	if brnger.batchSize != uint32(slice.BatchSize()) {
		panic(fmt.Sprintf(
			"slice has the wrong batch size: expected %v, got %v",
			brnger.batchSize, slice.BatchSize(),
		))
	}

	// Higher level checks ensure that the Element's within a slice have
	// the correct index. So at the lower level, BRNG state machine can
	// proceed without checking them
	if !slice.HasValidForm() {
		panic("slice has invalid form")
	}

	commitments := make([]shamir.Commitment, brnger.batchSize)
	for i, col := range slice {
		var commitment shamir.Commitment
		commitment.Set(col[0].Commitment())
		for _, e := range col[1:] {
			commitment.Add(commitment, e.Commitment())
		}
		commitments[i].Set(commitment)
	}

	// This checks the validity of every element in every column of the slice
	// Faults are an array of elements that fail the validity check
	faults := slice.Faults(brnger.h)
	if faults != nil {
		return nil, commitments, faults
	}

	// Construct the output share(s).
	shares := make(shamir.VerifiableShares, brnger.batchSize)
	for i, col := range slice {
		share := col[0].Share()
		for _, e := range col[1:] {
			summand := e.Share()
			share.Add(&share, &summand)
		}
		shares[i] = share
	}

	return shares, commitments, nil
}
