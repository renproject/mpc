package brng

import (
	"fmt"
	"math/rand"
	"reflect"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/surge"

	"github.com/renproject/mpc/brng/table"
)

type BRNGer struct {
	batchSize uint32
	h         secp256k1.Point
}

// BatchSize returns the expected batch size of the state machine.
func (brnger BRNGer) BatchSize() uint32 {
	return brnger.batchSize
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

// TransitionSlice performs the state transition for the BRNger state machine
// upon receiving a slice.
func (brnger *BRNGer) TransitionSlice(slice table.Slice) (shamir.VerifiableShares, []shamir.Commitment, []table.Element) {
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
		commitments[i] = col.CommitmentSum()
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
		shares[i] = col.ShareSum()
	}

	return shares, commitments, nil
}

// Generate implements the quick.Generator interface.
func (brnger BRNGer) Generate(_ *rand.Rand, _ int) reflect.Value {
	batchSize := rand.Uint32()
	h := secp256k1.RandomPoint()
	return reflect.ValueOf(BRNGer{batchSize, h})
}

// SizeHint implements the surge.SizeHinter interface.
func (brnger BRNGer) SizeHint() int {
	return surge.SizeHint(brnger.batchSize) +
		brnger.h.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (brnger BRNGer) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := surge.MarshalU32(uint32(brnger.batchSize), buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling batchSize: %v", err)
	}
	buf, rem, err = brnger.h.Marshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling h: %v", err)
	}
	return buf, rem, nil
}

// Unmarshal implements the surge.Unmarshaler interface.
func (brnger *BRNGer) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := surge.UnmarshalU32(&brnger.batchSize, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling batchSize: %v", err)
	}
	buf, rem, err = brnger.h.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling h: %v", err)
	}
	return buf, rem, nil
}
