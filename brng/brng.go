package brng

import (
	"fmt"
	"math/rand"
	"reflect"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/shamirutil"
	"github.com/renproject/surge"

	"github.com/renproject/mpc/brng/table"
)

// State is an enumeration of the possible states for the BRNG state machine.
type State uint8

// Constants that represent the different possible states for the BRNGer.
const (
	Init = State(iota)
	Waiting
	Ok
	Error
)

// String implements the Stringer interface.
func (s State) String() string {
	switch s {
	case Init:
		return "Init"
	case Waiting:
		return "Waiting"
	case Ok:
		return "Ok"
	case Error:
		return "Error"
	default:
		return fmt.Sprintf("Unknown(%v)", uint8(s))
	}
}

// SizeHint implements the surge.SizeHinter interface.
func (s State) SizeHint() int { return 1 }

// Marshal implements the surge.Marshaler interface.
func (s State) Marshal(buf []byte, rem int) ([]byte, int, error) {
	return surge.MarshalU8(uint8(s), buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (s *State) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	return surge.UnmarshalU8((*uint8)(s), buf, rem)
}

// BRNGer represents the state machine for the BRNG algorithm. The state
// machine can be used for an arbitrary number of invocations of BRNG, however
// each instance is specific to the indices that it was constructed with.
//
// The state machine augments the BRNG algorithm by adding a batch size. This
// allows the algorithm to be run a given number of times in parallel, making
// more efficient use of the consensus algorithm.
//
// There are four different states:
//	- Init
//	- Waiting
//	- Ok
//	- Error
//
// and state transitions are triggered by three different types of messages:
//	- Start(k, b)
//	- Slice
//	- Reset
//
// The state transitions are as follows:
//	- Init
//		- Start(k, b) 	-> Waiting
//		- Reset			-> Init
//		- Otherwise		-> Do nothing
//
//	- Waiting
//		- Valid slice 		-> Ok
//		- Invalid slice 	-> Error
//		- Reset				-> Init
//		- Otherwise 		-> Do nothing
//
//	- Ok
//		- Reset			-> Init
//		- Otherwise 	-> Do nothing
//
//	- Error
//		- Reset			-> Init
//		- Otherwise 	-> Do nothing
type BRNGer struct {
	state     State
	batchSize uint32

	sharer  shamir.VSSharer
	checker shamir.VSSChecker
}

// Generate implements the quick.Generator interface.
func (brnger BRNGer) Generate(_ *rand.Rand, _ int) reflect.Value {
	indices := shamirutil.RandomIndices(rand.Intn(20))
	h := secp256k1.RandomPoint()
	return reflect.ValueOf(New(indices, h))
}

// SizeHint implements the surge.SizeHinter interface.
func (brnger BRNGer) SizeHint() int {
	return brnger.state.SizeHint() +
		surge.SizeHint(brnger.batchSize) +
		brnger.sharer.SizeHint() +
		brnger.checker.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (brnger BRNGer) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := brnger.state.Marshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling state: %v", err)
	}
	buf, rem, err = surge.MarshalU32(uint32(brnger.batchSize), buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling batchSize: %v", err)
	}
	buf, rem, err = brnger.sharer.Marshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling sharer: %v", err)
	}
	buf, rem, err = brnger.checker.Marshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("marshaling checker: %v", err)
	}
	return buf, rem, nil
}

// Unmarshal implements the surge.Unmarshaler interface.
func (brnger *BRNGer) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := brnger.state.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling state: %v", err)
	}
	buf, rem, err = surge.UnmarshalU32(&brnger.batchSize, buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling batchSize: %v", err)
	}
	buf, rem, err = brnger.sharer.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling sharer: %v", err)
	}
	buf, rem, err = brnger.checker.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("unmarshaling checker: %v", err)
	}
	return buf, rem, nil
}

// State returns the current state of the state machine.
func (brnger BRNGer) State() State {
	return brnger.state
}

// N returns the total number of players participating
// in the BRNG protocol
func (brnger BRNGer) N() int {
	return brnger.sharer.N()
}

// BatchSize returns the expected batch size of the state machine.
func (brnger BRNGer) BatchSize() uint32 {
	return brnger.batchSize
}

// New creates a new BRNG state machine for the given indices and pedersen
// parameter h.
func New(indices []secp256k1.Fn, h secp256k1.Point) BRNGer {
	state := Init

	indicesCopy := make([]secp256k1.Fn, len(indices))
	copy(indicesCopy, indices)

	sharer := shamir.NewVSSharer(indicesCopy, h)
	checker := shamir.NewVSSChecker(h)

	// initialise the batch size as 0
	// it will be updated when state machine transitions to start
	return BRNGer{state, 0, sharer, checker}
}

// TransitionStart performs the state transition for the BRNGer state machine
// upon receiving a start message.
func (brnger *BRNGer) TransitionStart(k, b int) table.Row {
	if brnger.state != Init {
		return nil
	}

	row := table.MakeRow(brnger.sharer.N(), k, b)
	for i := range row {
		r := secp256k1.RandomFn()
		pointerToShares := row[i].BorrowShares()
		pointerToCommitment := row[i].BorrowCommitment()
		brnger.sharer.Share(pointerToShares, pointerToCommitment, r, k)
	}

	brnger.state = Waiting
	brnger.batchSize = uint32(b)

	return row
}

// TransitionSlice performs the state transition for the BRNger state machine
// upon receiving a slice.
func (brnger *BRNGer) TransitionSlice(slice table.Slice) (shamir.VerifiableShares, []shamir.Commitment, []table.Element) {
	if brnger.state != Waiting {
		return nil, nil, nil
	}

	if brnger.batchSize != uint32(slice.BatchSize()) {
		brnger.state = Error
		return nil, nil, nil
	}

	// Higher level checks ensure that the Element's within a slice have
	// the correct index. So at the lower level, BRNG state machine can
	// proceed without checking them
	if !slice.HasValidForm() {
		brnger.state = Error
		return nil, nil, nil
	}

	// This checks the validity of every element in every column of the slice
	// Faults are an array of elements that fail the validity check
	faults := slice.Faults(&brnger.checker)
	if faults != nil {
		brnger.state = Error

		return nil, nil, faults
	}

	// Construct the output share(s).
	shares := make(shamir.VerifiableShares, brnger.batchSize)
	commitments := make([]shamir.Commitment, brnger.batchSize)
	for i, col := range slice {
		shares[i], commitments[i] = col.Sum()
	}

	brnger.state = Ok
	return shares, commitments, nil
}

// Reset sets the state of the state machine to the Init state.
func (brnger *BRNGer) Reset() {
	brnger.state = Init
}
