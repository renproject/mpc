package rkpg

import (
	"io"

	"github.com/renproject/secp256k1-go"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/curve"
	"github.com/renproject/surge"

	"github.com/renproject/mpc/open"
	"github.com/renproject/mpc/rng"
)

// RKPGer describes the structure of the Random KeyPair Generation machine
// TODO: document
type RKPGer struct {
	// state signifies the current state of the RKPG state machine
	state State

	// h denotes the Pedersen Commitment Scheme Parameter
	h curve.Point

	// rnger signifies the RNGer embedded within the RKPG state machine. Every
	// invocation of random keypair generation requires an under-the-hood
	// invocation of random number generation, whose shares are later revealed
	// in order to construct the random keypair
	rnger rng.RNGer

	// rnger signifies the RZGer embedded within the RKPG state machine. In order
	// to open the underlying share's decommitments (to compute the random number
	// "in the exponent"), we do a share-hiding opening by masking the shares to
	// the secret decommitment with random shares of a zero secret
	rzger rng.RNGer

	// opener signifies the Opener state machine operating within the RKPG
	// state machine. As the RKPG machine receives openings from other machines,
	// the opener machine also transitions, to eventually reconstruct the
	// shared secret
	opener open.Opener

	// publicKeys hold the batch of public keys that will be computed once
	// RKPGer's share-hiding secrets are reconstructed
	publicKeys []curve.Point
}

// SizeHint implements the surge SizeHinter interface
func (rkpger RKPGer) SizeHint() int {
	return rkpger.state.SizeHint() +
		rkpger.h.SizeHint() +
		rkpger.rnger.SizeHint() +
		rkpger.rzger.SizeHint() +
		rkpger.opener.SizeHint() +
		surge.SizeHint(rkpger.publicKeys)
}

// Marshal implements the surge Marshaler interface
func (rkpger RKPGer) Marshal(w io.Writer, m int) (int, error) {
	// TODO:
	return m, nil
}

// Unmarshal implements the surge Unmarshaler interface
func (rkpger *RKPGer) Unmarshal(r io.Reader, m int) (int, error) {
	// TODO:
	return m, nil
}

// State returns the current state of the RKPGer state machine
func (rkpger RKPGer) State() State {
	return rkpger.state
}

// N returns the number of machine replicas participating in the RKPG protocol
func (rkpger RKPGer) N() int {
	return rkpger.rnger.N()
}

// BatchSize returns the batch size of the RKPG state machine.
// This also denotes the number of random keypairs that can possibly
// be generated in a single successful invocation of random keypair generation
func (rkpger RKPGer) BatchSize() uint32 {
	return rkpger.rnger.BatchSize()
}

// Threshold returns the reconstruction threshold for every set of shamir
// secret sharing
func (rkpger RKPGer) Threshold() uint32 {
	return rkpger.rnger.Threshold()
}

// New creates a new RKPG state machine for a given batch size
//
// ownIndex is the current machine's index
// indices is the set of player indices
// b is the number of random keypairs generated in one invocation of RKPG protocol
//   also termed the batch size of the RKPGer
// k is the reconstruction threshold for every shamir secret sharing, or the
//   minimum number of valid shares required to reconstruct the underlying secret
// h is the Pedersen Commitment Parameter, a point on elliptic curve
func New(
	ownIndex open.Fn,
	indices []open.Fn,
	b, k uint32,
	h curve.Point,
) (TransitionEvent, RKPGer) {
	// Assign the initial state to the RKPGer
	state := Init

	// Panic if we cannot even initialise the embedded RNGer
	event, rnger := rng.New(ownIndex, indices, b, k, h)
	if event != rng.Initialised {
		panic("RNGer initialisation failed")
	}

	// Panic if we cannot even initialise the embedded RZGer
	event, rzger := rng.New(ownIndex, indices, b, k, h)
	if event != rng.Initialised {
		panic("RZGer initialisation failed")
	}

	// Create a new instance of an Opener
	opener := open.New(b, indices, h)

	// Allocate memory for the public keys
	publicKeys := make([]curve.Point, int(b))
	for i := 0; i < int(b); i++ {
		publicKeys[i] = curve.New()
	}

	return Initialised, RKPGer{
		state:      state,
		h:          h,
		rnger:      rnger,
		rzger:      rzger,
		opener:     opener,
		publicKeys: publicKeys,
	}
}

// TransitionRNGShares accepts the BRNG outputs for RNG, and passes them on to
// the embedded RNGer. The RKPGer transitions to WaitingRNG on success. The machine
// can also transition to a RNGsReady state for the trivial case of reconstruction
// threshold being equal to one
//
// setsOfShares are the batch of verifiable shares from BRNG output
// setsOfCommitments are the corresponding batch of commitments for the shares
func (rkpger *RKPGer) TransitionRNGShares(
	setsOfShares []shamir.VerifiableShares,
	setsOfCommitments [][]shamir.Commitment,
) TransitionEvent {
	// Ignore if the RKPGer is not in the appropriate state
	if rkpger.state != Init {
		return RNGInputsIgnored
	}

	// Pass the shares and commitments to the embedded RNGer
	event := rkpger.rnger.TransitionShares(setsOfShares, setsOfCommitments, false)

	// If the local commitments/shares were constructed, transition to the next
	// state and emit an appropriate event representing the progress made
	if event == rng.CommitmentsConstructed || event == rng.SharesConstructed {
		rkpger.state = WaitingRNG
		return RNGInputsAccepted
	}

	// If this was a trivial case where k = 1, transition to the appropriate state
	// while emitting the appropriate event representing the progress made
	if event == rng.RNGsReconstructed {
		rkpger.state = RNGsReady
		return RNGReady
	}

	// If none of the above scenarios matched, it means the inputs were invalid
	// in one or more ways and hence we ignore them
	return RNGInputsIgnored
}

// TransitionRNGOpen accepts openings from other machines for reconstructing the
// unbiased random number shares. The RKPGer continues to be in the WaitingRNG
// state until reconstructing its shares, upon which it transitions to RNGsReady
//
// fromIndex is the machine index of the open sender
// openings are the verifiable shares opened to the current machine
func (rkpger *RKPGer) TransitionRNGOpen(
	fromIndex open.Fn,
	openings shamir.VerifiableShares,
) TransitionEvent {
	// Ignore if the RKPGer is not in the appropriate state
	if rkpger.state != WaitingRNG {
		return RNGOpeningsIgnored
	}

	// Pass the openings to the embedded RNGer
	event := rkpger.rnger.TransitionOpen(fromIndex, openings)

	// If the openings were added, emit an appropriate event. This means the
	// reconstruction was not yet possible and the embedded RNGer will continue
	// waiting for more openings
	if event == rng.OpeningsAdded {
		return RNGOpeningsAccepted
	}

	// If the underlying secrets were reconstructed, it means the RNG
	// protocol is complete.
	// Transition to the appropriate state while emitting the appropriate
	// event representing the progress made
	if event == rng.RNGsReconstructed {
		rkpger.state = RNGsReady
		return RNGReady
	}

	// If none of the above scenarios matched, it means the openings were
	// marked invalid in one or more ways and hence were ignored
	return RNGOpeningsIgnored
}

// TransitionRZGShares accepts the BRNG outputs for RZG, and passes them on to
// the embedded RZGer. The RKPGer transitions to WaitingRZG on success. The machine
// can also transition to a WaitingOpen state for the trivial case of reconstruction
// threshold being equal to one
//
// setsOfShares are the batch of verifiable shares from BRNG output
// setsOfCommitments are the corresponding batch of commitments for the shares
func (rkpger *RKPGer) TransitionRZGShares(
	setsOfShares []shamir.VerifiableShares,
	setsOfCommitments [][]shamir.Commitment,
) TransitionEvent {
	// Ignore if the RKPGer is not in the appropriate state
	if rkpger.state != RNGsReady {
		return RZGInputsIgnored
	}

	// Pass the shares and commitments to the embedded RZGer
	event := rkpger.rzger.TransitionShares(setsOfShares, setsOfCommitments, true)

	// If the local commitments/shares were constructed, transition to the next
	// state and emit an appropriate event representing the progress made
	if event == rng.CommitmentsConstructed || event == rng.SharesConstructed {
		rkpger.state = WaitingRZG
		return RZGInputsAccepted
	}

	// If this was a trivial case where k = 1, compute the commitments for the
	// share-hiding opening to follow and reset the RKPGer's embedded opener.
	// Also, transition to the appropriate state while emitting the appropriate
	// event representing the progress made
	if event == rng.RNGsReconstructed {
		rkpger.resetOpener()
		rkpger.state = WaitingOpen
		return RZGReady
	}

	// If none of the above scenarios matches, it means the inputs were invalid
	// in one or more ways and hence we ignore them
	return RZGInputsIgnored
}

// TransitionRZGOpen accepts openings from other machines for reconstructing the
// random shares for zero sharing. The RKPGer continues to be in the WaitingRZG
// state until reconstructing its shares, upon which it transitions to WaitingOpen
//
// fromIndex is the machine index of the open sender
// openings are the verifiable shares opened to the current machine
func (rkpger *RKPGer) TransitionRZGOpen(
	fromIndex open.Fn,
	openings shamir.VerifiableShares,
) TransitionEvent {
	// Ignore if the RKPGer is not in the appropriate state
	if rkpger.state != WaitingRZG {
		return RZGOpeningsIgnored
	}

	// Pass the openings to the embedded RZGer
	event := rkpger.rzger.TransitionOpen(fromIndex, openings)

	// If the openings were added, emit an appropriate event. This means the
	// reconstruction was not yet possible and the embedded RZGer will continue
	// waiting for more openings
	if event == rng.OpeningsAdded {
		return RZGOpeningsAccepted
	}

	// If the underlying secrets were reconstructed, it means the RZG
	// protocol is complete. We then compute the commitments for the
	// share-hiding opening to follow and reset the RKPGer's embedded opener.
	// Also, transition to the appropriate state while emitting the appropriate
	// event representing the progress made
	if event == rng.RNGsReconstructed {
		rkpger.resetOpener()
		rkpger.state = WaitingOpen
		return RZGReady
	}

	// If none of the above scenarios matched, it means the openings were
	// marked invalid in one or more ways and hence were ignored
	return RZGOpeningsIgnored
}

// TransitionHidingOpenings accepts the share-hiding openings from other machines
// in the network participating in the RKPG protocol. Valid openings are added
// to the RKPGer's embedded Opener, and once k valid openings are available,
// the Opener reconstructs the underlying secrets.
func (rkpger *RKPGer) TransitionHidingOpenings(
	openings shamir.VerifiableShares,
) TransitionEvent {
	// Ignore if the RKPGer is not in appropriate state
	if rkpger.state != WaitingOpen {
		return HidingOpeningsIgnored
	}

	// Pass the openings to the embedded Opener
	event := rkpger.opener.TransitionShares(openings)

	// If the shares were successfully added to the Opener's buffer
	// emit an event representing this progress
	if event == open.SharesAdded {
		return HidingOpeningsAccepted
	}

	// If the shares were in fact the kth, and reconstruction was successful,
	// compute the random keypairs, transition to the Done state and emit
	// an event representing this progress
	if event == open.Done {
		rkpger.computeKeyPairs()
		rkpger.state = Done
		return KeyPairsReady
	}

	// If none of the above scenarios were satisfied, the openings were invalid
	// in one or more ways, and hence were ignored by the Opener
	return HidingOpeningsIgnored
}

// Reset transitions a RKPGer in any state to the Init state
func (rkpger *RKPGer) Reset() TransitionEvent {
	// If the embedded RNG cannot be reset, abort the operation
	event := rkpger.rnger.Reset()
	if event != rng.Reset {
		return ResetAborted
	}

	// If the embedded RZG cannot be reset, abort the operation
	event = rkpger.rzger.Reset()
	if event != rng.Reset {
		return ResetAborted
	}

	// Reset the public key points
	newPoint := curve.New()
	for _, publicKey := range rkpger.publicKeys {
		publicKey.Set(&newPoint)
	}

	// The reset operation was successful, so transition to the appropriate
	// state and emit the appropriate event
	rkpger.state = Init
	return ResetDone
}

// DirectedRNGOpenings returns the RNG specific directed openings from this
// machine to another specified machine in the RKPG protocol
func (rkpger RKPGer) DirectedRNGOpenings(to open.Fn) shamir.VerifiableShares {
	return rkpger.rnger.DirectedOpenings(to)
}

// DirectedRZGOpenings returns the RZG specific directed openings from this
// machine to another specified machine in the RKPG protocol
func (rkpger RKPGer) DirectedRZGOpenings(to open.Fn) shamir.VerifiableShares {
	return rkpger.rzger.DirectedOpenings(to)
}

// HidingOpenings returns the share-hiding openings from this RKPGer machine
func (rkpger RKPGer) HidingOpenings() shamir.VerifiableShares {
	// Ignore if the RKPGer is not in appropriate state
	if rkpger.state != WaitingOpen {
		return nil
	}

	// Fetch shares to the RNG and RZG
	rngShares := rkpger.rnger.ReconstructedShares()
	rzgShares := rkpger.rzger.ReconstructedShares()

	// Add both the RNG and RZG shares to construct the share-hiding openings
	// s_i = r_i + z_i
	hidingOpenings := make(shamir.VerifiableShares, rkpger.BatchSize())
	for i, rngShare := range rngShares {
		hidingOpenings[i].Add(&rngShare, &rzgShares[i])
	}

	return hidingOpenings
}

// KeyPairs returns a tuple of the reconstructed batch of random keypairs
// and the RKPGer's own share of the corresponding unbiased random numbers
func (rkpger RKPGer) KeyPairs() ([]curve.Point, shamir.VerifiableShares) {
	// Return nil values if the RKPGer is not in the Done state
	if rkpger.state != Done {
		return nil, nil
	}

	// Copy the public keys
	publicKeysCopy := make([]curve.Point, rkpger.BatchSize())
	copy(publicKeysCopy, rkpger.publicKeys)

	// Copy the machine's shares for the unbiased random numbers
	sharesCopy := make(shamir.VerifiableShares, rkpger.BatchSize())
	copy(sharesCopy, rkpger.rnger.ReconstructedShares())

	return publicKeysCopy, sharesCopy
}

// Private functions

// resetOpener is called once RZG is done. At this stage, the RKPGer has
// the required information to compute the final set of commitments for the
// share-hiding opening, and reset its Opener with these commitments
func (rkpger *RKPGer) resetOpener() {
	// Fetch commitments from RNG and RZG
	rngComms := rkpger.rnger.Commitments()
	rzgComms := rkpger.rzger.Commitments()

	// Because we're doing a share-hiding opening, the new share
	// s_i = r_i + z_i
	// Hence, we also need to add the corresponding commitments
	// to compute the commitment for the share-hiding opening
	comms := make([]shamir.Commitment, rkpger.BatchSize())
	for i, rngComm := range rngComms {
		comms[i] = shamir.NewCommitmentWithCapacity(int(rkpger.Threshold()))
		comms[i].Add(&rngComm, &rzgComms[i])
	}
	rkpger.opener.TransitionReset(comms)

	// Initialise the public keys to be the first point of each commitment.
	// These will be later scaled by the reconstructed decommitments from the
	// share-hiding opening
	for i, comm := range comms {
		point := comm.GetPoint(0)
		rkpger.publicKeys[i].Set(&point)
	}
}

// computeKeyPairs is called once the share-hiding opening is done and
// the decommitments were reconstructed. This function uses those decommitments
// to scale the initialised public keys and compute the random keypairs
func (rkpger *RKPGer) computeKeyPairs() {
	// Fetch the reconstructed batch of decommitments
	// This is the batch of t_0's
	decomms := rkpger.opener.Decommitments()

	// For each of the initialised public keys, scale them to reveal the
	// unbiased random numbers "in the exponent", i.e. the random public keys
	for i := 0; i < len(rkpger.publicKeys); i++ {
		// Compute the negation of t_0, i.e. (-t_0)
		var decommInv secp256k1.Secp256k1N
		decommInv.Neg(&decomms[i], 1)
		decommInv.Normalize()

		// Get the bytes representation of (-t_0)
		var decommInvBytes [32]byte
		decommInv.GetB32(decommInvBytes[:])

		// Scale the Pedersen Commitment Scheme Parameter
		// h^(-t_0)
		hPow := curve.New()
		hPow.Scale(&rkpger.h, decommInvBytes)

		// Add this to the initialised public key
		// g^(c_0) . h^(t_0) . h^(-t_0) = g^(c_0)
		rkpger.publicKeys[i].Add(&rkpger.publicKeys[i], &hPow)
	}
}
