package rkpg

import (
	"github.com/renproject/shamir/curve"

	"github.com/renproject/mpc/open"
	"github.com/renproject/mpc/rng"
)

// RKPGer describes the structure of the Random KeyPair Generation machine
type RKPGer struct {
	// state signifies the current state of the RKPG state machine
	state State

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
) RKPGer {
	state := Init
	_, rnger := rng.New(ownIndex, indices, b, k, h)
	_, rzger := rng.New(ownIndex, indices, b, k, h)
	opener := open.New(b, indices, h)

	return RKPGer{
		state:  state,
		rnger:  rnger,
		rzger:  rzger,
		opener: opener,
	}
}
