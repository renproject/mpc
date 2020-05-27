package rng

import (
	"fmt"
	"io"

	"github.com/renproject/secp256k1-go"
	"github.com/renproject/shamir"
	"github.com/renproject/surge"
)

// Fn represents a convenience type for Secp256k1N
type Fn secp256k1.Secp256k1N

// State is an enumeration of the possible states for the RNG state machine
type State uint8

// Constants that represent the different possible states for RNGer
const (
	// Init signifies that the RNG state machine is in the initialises state
	Init = State(iota)

	// WaitingOpen signifies that the RNG state machine is waiting for more
	// openings from other players in the network. It does not say anything
	// about whether or not the machine itself has constructed its own shares
	WaitingOpen

	// Done signifies that the RNG state machine has received `k` share openings,
	// that may or may not include the machine's own share. It also signifies
	// that the state machine now holds and can respond with `b` unbiased random numbers
	Done
)

// String implements the Stringer interface
func (s State) String() string {
	switch s {
	case Init:
		return "Init"
	case WaitingOpen:
		return "WaitingOpen"
	case Done:
		return "Done"
	default:
		return fmt.Sprintf("Unknown state (%v)", uint8(s))
	}
}

// SizeHint implements the surge.SizeHinter interface
func (s State) SizeHint() int { return 1 }

// Marshal implements the surge.Marshaler interface
func (s State) Marshal(w io.Writer, m int) (int, error) {
	return surge.Marshal(w, uint8(s), m)
}

// Unmarshal implements the surge.Unmarshaler interface
func (s *State) Unmarshal(r io.Reader, m int) (int, error) {
	return surge.Unmarshal(r, (*uint8)(s), m)
}

// TransitionEvent represents the different outcomes that can occur when
// the state machine receives and processes shares/openings
type TransitionEvent uint8

const (
	// Initialised represents the event returned when the RNG state machine
	// is initialised and hence is now in the Init state
	Initialised = TransitionEvent(iota)

	// SharesIgnored represents the event returned when the RNG state machine
	// received `b` sets of verifiable shares that were invalid in some way
	SharesIgnored

	// SharesConstructed represents the event returned when the RNG state machine
	// received `b` valid sets of verifiable shares and it was able to
	// construct its own shares successfully
	SharesConstructed

	// OpeningsIgnored represents the event returned when the RNG state machine
	// received directed openings that were invalid in some way
	OpeningsIgnored

	// OpeningsAdded represents the event returned when the RNG state machine
	// received valid directed openings and hence added them to its sets of openings
	OpeningsAdded

	// RNGsReconstructed represents the event returned when the RNG state machine
	// received the `k` set of directed openings and hence was able to reconstruct
	// `b` random numbers. This also signifies that the RNG state machine has now
	// transitioned to the `Done` state and holds the reconstructed unbiased random numbers
	RNGsReconstructed
)

// RNGer describes the structure of the Random Number Generation machine
type RNGer struct {
	state     State
	batchSize uint32
	threshold uint32
}

// SizeHint implements the surge.SizeHinter interface
func (rnger RNGer) SizeHint() int {
	return rnger.state.SizeHint() +
		surge.SizeHint(rnger.batchSize) +
		surge.SizeHint(rnger.threshold)
}

// Marshal implements the surge.Marshaler interface
func (rnger RNGer) Marshal(w io.Writer, m int) (int, error) {
	m, err := rnger.state.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("marshaling state: %v", err)
	}
	m, err = surge.Marshal(w, uint32(rnger.batchSize), m)
	if err != nil {
		return m, fmt.Errorf("marshaling batchSize: %v", err)
	}
	m, err = surge.Marshal(w, uint32(rnger.threshold), m)
	if err != nil {
		return m, fmt.Errorf("marshaling threshold: %v", err)
	}
	return m, nil
}

// Unmarshal implements the surge.Unmarshaler interface
func (rnger *RNGer) Unmarshal(r io.Reader, m int) (int, error) {
	m, err := rnger.state.Unmarshal(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling state: %v", err)
	}
	m, err = surge.Unmarshal(r, &rnger.batchSize, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling batchSize: %v", err)
	}
	m, err = surge.Unmarshal(r, &rnger.threshold, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling threshold: %v", err)
	}
	return m, nil
}

// State returns the current state of the RNGer state machine
func (rnger RNGer) State() State {
	return rnger.state
}

// BatchSize returns the batch size of the RNGer state machine.
// This also denotes the number of random numbers that can possibly
// be generated after a successful execution of all state transitions
func (rnger RNGer) BatchSize() uint32 {
	return rnger.batchSize
}

// Threshold returns the reconstruction threshold for every set of shares.
// This is the same as `k`, or the minimum number of openings required
// to be able to reconstruct the random numbers
func (rnger RNGer) Threshold() uint32 {
	return rnger.threshold
}

// New creates a new RNG state machine for a given batch size
func New(b, k uint32) (TransitionEvent, RNGer) {
	state := Init

	return Initialised, RNGer{state, b, k}
}

// TransitionShares performs the state transition for the RNG state machine
// from `Init` to `WaitingOpen`, upon receiving `b` sets of verifiable shares
// and their respective commitments.
// The machine should locally compute its own shares from the received sets of shares
func (rnger *RNGer) TransitionShares(
	setsOfShares []shamir.VerifiableShares,
	setsOfCommitments [][]shamir.Commitment,
) TransitionEvent {
	// Ignore the shares if their number of sets does not match
	// the number of sets of commitments
	if len(setsOfShares) != len(setsOfCommitments) {
		return SharesIgnored
	}

	// Ignore the shares if their number of sets does not match
	// the batch size of the RNG state machine
	if len(setsOfShares) != int(rnger.batchSize) {
		return SharesIgnored
	}

	return SharesIgnored
}

// HasConstructedShares returns `true` if the RNG machine has received its `b` sets
// of verifiable shares, and upon that constructed its shares. It returns false otherwise
func (rnger RNGer) HasConstructedShares(bID uint32) bool {
	return false
}

// TransitionOpen performs the state transition for the RNG state machine upon
// receiving directed openings of shares from other players.
//
// The state transition on calling TransitionOpen is described below:
// 1. RNG machine in state `Init` transitions to `WaitingOpen`
// 2. RNG machine in state `WaitingOpen` continues to be in state `WaitingOpen`
//    if the machine has less than `k` opened shares, including the one supplied here.
// 3. RNG machine in state `WaitingOpen` transitions to `Done` if the machine
//    now has `k` opened shares, including the one supplied here.
//
// Since the RNG machine is capable of generating `b` random numbers, we expect
// other players to supply `b` directed openings of their shares too.
func (rnger *RNGer) TransitionOpen(
	index Fn,
	openings shamir.VerifiableShares,
	commitments []shamir.Commitment,
) TransitionEvent {
	return OpeningsIgnored
}

// ReconstructedRandomNumbers returns the `b` random numbers that have been
// reconstructed by the RNG machine. This also means that the RNG machine is in
// the `Done` state. If it isn't this returns `nil`
func (rnger RNGer) ReconstructedRandomNumbers() []Fn {
	return nil
}

// ReconstructedRandomNumber returns the `bId`th random number that has been
// reconstructed by the RNG machine. This also means that the RNG machine is in
// the `Done` state. If it isn't this returns empty instance of Fn
func (rnger RNGer) ReconstructedRandomNumber(bID uint32) Fn {
	return Fn{}
}
