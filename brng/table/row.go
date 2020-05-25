package table

import (
	"io"

	"github.com/renproject/shamir"
	"github.com/renproject/surge"
)

// A Row represents a batch of Sharings that one player generates during BRNG.
type Row []Sharing

// SizeHint implements the surge.SizeHinter interface.
func (row Row) SizeHint() int {
	return surge.SizeHint([]Sharing(row))
}

// Marshal implements the surge.Marshaler interface.
func (row Row) Marshal(w io.Writer, m int) (int, error) {
	return surge.Marshal(w, []Sharing(row), m)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (row *Row) Unmarshal(r io.Reader, m int) (int, error) {
	return surge.Unmarshal(r, (*[]Sharing)(row), m)
}

// MakeRow allocates and returns a new empty row.
func MakeRow(n, k, b int) Row {
	sharings := make([]Sharing, b)
	for i := range sharings {
		sharings[i].shares = make(shamir.VerifiableShares, n)
		sharings[i].commitment = shamir.NewCommitmentWithCapacity(k)
	}

	return sharings
}

// BatchSize returns the batch number (the number of sharings) for the given
// Row.
func (row Row) BatchSize() int { return len(row) }

// N returns the number of shares in a any given Sharing of the given Row. If
// there are no sharings, or if not all of the sharings have the same number of
// shares, -1 is returned instead.
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
