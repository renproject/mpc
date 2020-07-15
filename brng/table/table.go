package table

// The goal of BRNG is to generate a batch of biased random numbers. At the end
// of running the BRNG protocol successfully, we should have `b` biased random
// numbers (also called the `batch size` of the BRNGer).
//
// Each of those biased random numbers is produced by the contribution of shares
// from all players participating in the protocol. Generally, we would say, `n`
// players contribute a set of `n` shares for a random number, such that each
// random number is represented by `k-1` degree polynomial.
//
// The protocol can be visualised by the illustration below.
//
//                            Slice
//                              |
//                           ___|__________________
//                         /    |   /|/|           /|
//                       /      V / /| | <-- Col /  |
//                     /        / /  | |       /    |
//                   /_______ /_/____|_|____ /     /|
//                   |       | |     | |    |    / /|
//                ^  |       | |     | |    |  / / <--- Row
//                |  |_______|_|_____|_|____|/ /    |
//           From |  |_|_E_|_|_|_|_|_|_|_|__|/      |
//                |  |       | |     | |    |       |
//                   |       | |    / /     |      /
//                   |       | |  / /       |    /   Batch
//                   |       | |/ /         |  /
//                   |_______|/|/___________|/
//                          ------>
//                            To
//
// Sharing holds the set of verifiable shares from a single player representing
// a single random number.
//
// Row defines a batch of Sharings, all coming from a single player. So a row
// would hold the `b` sets of verifiable shares, basically, the player's potential
// contribution for `b` biased random numbers.
//
// Element is a single verifiable share, marked as `E` in the above diagram. We
// therefore require a `from` field in an element, to tell us which player this
// verifiable share comes from.
//
// Col defines a list of elements, but specific to a particular index. It holds
// the jth share from each of the players.
//
// Slice is vertical slice of the above cube. It represents shares from all players
// for a specific index (Col) and `b` such Cols. Therefore a slice is basically
// a list of Cols.

import (
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/surge"
)

// A Table represents all of the shares across all players for a given run of
// the BRNG algorithm.
type Table []Row

// SizeHint implements the surge.SizeHinter interface.
func (t Table) SizeHint() int { return surge.SizeHint([]Row(t)) }

// Marshal implements the surge.Marshaler interface.
func (t Table) Marshal(buf []byte, rem int) ([]byte, int, error) {
	return surge.Marshal([]Row(t), buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (t *Table) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	return surge.Unmarshal((*[]Row)(t), buf, rem)
}

// TakeSlice returns the Slice for the given index in the table.
func (t Table) TakeSlice(index secp256k1.Fn, fromIndices []secp256k1.Fn) Slice {
	// NOTE: Assumes that the table is well formed.
	slice := make(Slice, t.BatchSize())
	for i := range slice {
		slice[i] = make(Col, t.Height())
	}

	// Get the integer index of the given index.
	ind := -1
	for i := range fromIndices {
		if index.Eq(&fromIndices[i]) {
			ind = i
		}
	}
	if ind == -1 {
		panic("index missing from fromIndices")
	}

	for i, row := range t {
		for j, sharing := range row {
			var commitment shamir.Commitment

			from := fromIndices[i]
			share := sharing.shares[ind]
			commitment.Set(sharing.Commitment())

			slice[j][i] = NewElement(from, share, commitment)
		}
	}

	return slice
}

// Height returns the number of different players that contributed rows to the
// table.
func (t Table) Height() int {
	return len(t)
}

// BatchSize returns the size of the batch of the table. If the table has no
// rows, or if not all of the rows have the same batch size, -1 is returned
// instead.
func (t Table) BatchSize() int {
	if t.Height() == 0 {
		return -1
	}

	b := len(t[0])
	for i := 1; i < len(t); i++ {
		if len(t[i]) != b {
			return -1
		}
	}

	return b
}

// HasValidDimensions returns true if each of the three dimensions of the table
// are valid and consistent. If any of the dimensions are 0, or if there are
// any inconsistencies in the dimensions, this function will return false.
func (t Table) HasValidDimensions() bool {
	if t.BatchSize() == -1 {
		return false
	}

	n := t[0].N()
	if n == -1 {
		return false
	}
	for i := 1; i < len(t); i++ {
		if t[i].N() != n {
			return false
		}
	}

	return true
}
