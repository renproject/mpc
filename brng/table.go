package brng

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
	"errors"
	"fmt"
	"io"

	"github.com/renproject/secp256k1-go"
	"github.com/renproject/shamir"
	"github.com/renproject/surge"
)

type Sharing struct {
	shares     shamir.VerifiableShares
	commitment shamir.Commitment
}

// SizeHint implements the surge.SizeHinter interface.
func (sharing Sharing) SizeHint() int {
	return sharing.shares.SizeHint() + sharing.commitment.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (sharing Sharing) Marshal(w io.Writer, m int) (int, error) {
	m, err := sharing.shares.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("marshaling shares: %v", err)
	}
	m, err = sharing.commitment.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("marshaling commitment: %v", err)
	}
	return m, nil
}

// Unmarshal implements the surge.Unmarshaler interface.
func (sharing *Sharing) Unmarshal(r io.Reader, m int) (int, error) {
	m, err := sharing.shares.Unmarshal(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling shares: %v", err)
	}
	m, err = sharing.commitment.Unmarshal(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling commitment: %v", err)
	}
	return m, nil
}

func (sharing Sharing) Shares() shamir.VerifiableShares {
	return sharing.shares
}

func (sharing Sharing) Commitment() shamir.Commitment {
	return sharing.commitment
}

func (sharing Sharing) ShareWithIndex(index secp256k1.Secp256k1N) (shamir.VerifiableShare, error) {
	for _, share := range sharing.shares {
		s := share.Share()
		if s.IndexEq(&index) {
			return share, nil
		}
	}
	return shamir.VerifiableShare{}, errors.New("no share with the given index was found")
}

func (sharing Sharing) N() int { return len(sharing.shares) }

type Row []Sharing

// SizeHint implements the surge.SizeHinter interface.
func (row Row) SizeHint() int { return surge.SizeHint(row) }

// Marshal implements the surge.Marshaler interface.
func (row Row) Marshal(w io.Writer, m int) (int, error) {
	return surge.Marshal(w, row, m)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (row *Row) Unmarshal(r io.Reader, m int) (int, error) {
	return surge.Unmarshal(r, row, m)
}

func MakeRow(n, k, b int) Row {
	sharings := make([]Sharing, b)
	for i := range sharings {
		sharings[i].shares = make(shamir.VerifiableShares, n)
		sharings[i].commitment = shamir.NewCommitmentWithCapacity(k)
	}

	return sharings
}

func (row Row) BatchSize() int { return len(row) }

func (row Row) N() int {
	if row.BatchSize() == 0 {
		return -1
	}

	n := row[0].N()
	for i := 1; i < len(row); i++ {
		if row[i].N() != n {
			return -1
		}
	}

	return n
}

// TODO: Probably think of a better name.
type Element struct {
	from       secp256k1.Secp256k1N
	share      shamir.VerifiableShare
	commitment shamir.Commitment
}

// NewElement constructs a new Element from the given arguments.
func NewElement(
	from secp256k1.Secp256k1N,
	share shamir.VerifiableShare,
	commitment shamir.Commitment,
) Element {
	return Element{from, share, commitment}
}

// SizeHint implements the surge.SizeHinter interface.
func (e Element) SizeHint() int {
	return e.from.SizeHint() + e.share.SizeHint() + e.commitment.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (e Element) Marshal(w io.Writer, m int) (int, error) {
	m, err := e.from.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("marshaling from: %v", err)
	}
	m, err = e.share.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("marshaling share: %v", err)
	}
	m, err = e.commitment.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("marshaling commitment: %v", err)
	}
	return m, nil
}

// Unmarshal implements the surge.Unmarshaler interface.
func (e Element) Unmarshal(r io.Reader, m int) (int, error) {
	m, err := e.from.Unmarshal(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling from: %v", err)
	}
	m, err = e.share.Unmarshal(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling share: %v", err)
	}
	m, err = e.commitment.Unmarshal(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling commitment: %v", err)
	}
	return m, nil
}

func (e *Element) Set(other Element) {
	e.from = other.from
	e.share = other.share
	e.commitment.Set(other.commitment)
}

type Col []Element

// SizeHint implements the surge.SizeHinter interface.
func (col Col) SizeHint() int { return surge.SizeHint(col) }

// Marshal implements the surge.Marshaler interface.
func (col Col) Marshal(w io.Writer, m int) (int, error) {
	return surge.Marshal(w, col, m)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (col *Col) Unmarshal(r io.Reader, m int) (int, error) {
	return surge.Unmarshal(r, col, m)
}

func (col Col) HasValidForm() bool {
	if len(col) == 0 {
		return false
	}

	share := col[0].share.Share()
	for i := 1; i < len(col); i++ {
		// FIXME: Create and use an IndexEq method on the
		// shamir.VerifiableShare type.
		s := col[i].share.Share()
		index := s.Index()
		if !share.IndexEq(&index) {
			return false
		}
	}

	return true
}

type Slice []Col

// SizeHint implements the surge.SizeHinter interface.
func (slice Slice) SizeHint() int { return surge.SizeHint(slice) }

// Marshal implements the surge.Marshaler interface.
func (slice Slice) Marshal(w io.Writer, m int) (int, error) {
	return surge.Marshal(w, slice, m)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (slice *Slice) Unmarshal(r io.Reader, m int) (int, error) {
	return surge.Unmarshal(r, slice, m)
}

func (slice Slice) BatchSize() int {
	return len(slice)
}

func (slice Slice) HasValidForm() bool {
	for _, c := range slice {
		if !c.HasValidForm() {
			return false
		}
	}
	return true
}

func (slice Slice) Faults(checker *shamir.VSSChecker) []Element {
	var faults []Element
	for _, c := range slice {
		for _, e := range c {
			if !checker.IsValid(&e.commitment, &e.share) {
				var fault Element
				fault.Set(e)
				faults = append(faults, fault)
			}
		}
	}

	if len(faults) == 0 {
		return nil
	}

	return faults
}

type Table []Row

func (t Table) Height() int {
	return len(t)
}

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
