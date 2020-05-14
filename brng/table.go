package brng

import (
	"fmt"
	"io"

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

type Col struct {
	shares      shamir.VerifiableShares
	commitments []shamir.Commitment
}

// SizeHint implements the surge.SizeHinter interface.
func (col Col) SizeHint() int {
	return col.shares.SizeHint() + surge.SizeHint(col.commitments)
}

// Marshal implements the surge.Marshaler interface.
func (col Col) Marshal(w io.Writer, m int) (int, error) {
	m, err := col.shares.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("marshaling shares: %v", err)
	}
	m, err = surge.Marshal(w, col.commitments, m)
	if err != nil {
		return m, fmt.Errorf("marshaling commitments: %v", err)
	}
	return m, nil
}

// Unmarshal implements the surge.Unmarshaler interface.
func (col *Col) Unmarshal(r io.Reader, m int) (int, error) {
	m, err := col.shares.Unmarshal(r, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling shares: %v", err)
	}
	m, err = surge.Unmarshal(r, col.commitments, m)
	if err != nil {
		return m, fmt.Errorf("unmarshaling commitments: %v", err)
	}
	return m, nil
}

func (col Col) HasValidForm() bool {
	if len(col.shares) == 0 {
		return false
	}
	if len(col.shares) != len(col.commitments) {
		return false
	}

	share := col.shares[0].Share()
	for i := 1; i < len(col.shares); i++ {
		// FIXME: Create and use an IndexEq method on the
		// shamir.VerifiableShare type.
		s := col.shares[i].Share()
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
