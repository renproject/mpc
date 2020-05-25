package brng

import (
	"fmt"
	"io"

	"github.com/renproject/secp256k1-go"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/curve"
	"github.com/renproject/surge"
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
func (s State) Marshal(w io.Writer, m int) (int, error) {
	return surge.Marshal(w, uint8(s), m)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (s *State) Unmarshal(r io.Reader, m int) (int, error) {
	return surge.Unmarshal(r, (*uint8)(s), m)
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

// SizeHint implements the surge.SizeHinter interface.
func (brnger BRNGer) SizeHint() int {
	return brnger.state.SizeHint() +
		surge.SizeHint(brnger.batchSize) +
		brnger.sharer.SizeHint() +
		brnger.checker.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (brnger BRNGer) Marshal(w io.Writer, m int) (int, error) {
	m, err := brnger.state.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("marshaling state: %v", err)
	}
	m, err = surge.Marshal(w, uint32(brnger.batchSize), m)
	if err != nil {
		return m, fmt.Errorf("marshaling batchSize: %v", err)
	}
	m, err = brnger.sharer.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("marshaling sharer: %v", err)
	}
	m, err = brnger.checker.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("marshaling checker: %v", err)
	}
	return m, nil
}

// Unmarshal implements the surge.Unmarshaler interface.
func (brnger *BRNGer) Unmarshal(r io.Reader, m int) (int, error) {
	m, err := brnger.state.Unmarshal(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling state: %v", err)
	}
	m, err = surge.Unmarshal(r, &brnger.batchSize, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling batchSize: %v", err)
	}
	m, err = brnger.sharer.Unmarshal(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling sharer: %v", err)
	}
	m, err = brnger.checker.Unmarshal(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling checker: %v", err)
	}
	return m, nil
}

// State returns the current state of the state machine.
func (brnger *BRNGer) State() State {
	return brnger.state
}

// N returns the total number of players participating
// in the BRNG protocol
func (brnger *BRNGer) N() int {
	return brnger.sharer.N()
}

// BatchSize returns the expected batch size of the state machine.
func (brnger *BRNGer) BatchSize() uint32 {
	return brnger.batchSize
}

// New creates a new BRNG state machine for the given indices and pedersen
// parameter h.
func New(indices []secp256k1.Secp256k1N, h curve.Point) BRNGer {
	state := Init
	sharer := shamir.NewVSSharer(indices, h)
	checker := shamir.NewVSSChecker(h)

	// initialise the batch size as 0
	// it will be updated when state machine transitions to start
	return BRNGer{state, 0, sharer, checker}
}

// TransitionStart performs the state transition for the BRNGer state machine
// upon receiving a start message.
func (brnger *BRNGer) TransitionStart(k, b int) Row {
	if brnger.state != Init {
		return nil
	}

	row := MakeRow(brnger.sharer.N(), k, b)
	for i := range row {
		r := secp256k1.RandomSecp256k1N()
		brnger.sharer.Share(&row[i].shares, &row[i].commitment, r, k)
	}

	brnger.state = Waiting
	brnger.batchSize = uint32(b)

	return row
}

// TransitionSlice performs the state transition for the BRNger state machine
// upon receiving a slice.
func (brnger *BRNGer) TransitionSlice(slice Slice) (shamir.VerifiableShares, []shamir.Commitment, []Element) {
	if brnger.state != Waiting {
		return nil, nil, nil
	}

	if brnger.batchSize != uint32(slice.BatchSize()) {
		brnger.state = Error
		return nil, nil, nil
	}

	// TODO: The `faults` don't account for invalid index errors
	// Is it required to add them to the list of faults?
	if !slice.HasValidForm() {
		brnger.state = Error
		return nil, nil, nil
	}

	// TODO: Should we try to reconstruct on a per column basis? Or just give
	// up if any of the columns in the slice are invalid?
	faults := slice.Faults(&brnger.checker)
	if faults != nil {
		brnger.state = Error

		// TODO: Decide the best way to return the faults.
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
