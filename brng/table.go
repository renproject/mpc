package brng

import "github.com/renproject/shamir"

type Sharing struct {
	shares     shamir.VerifiableShares
	commitment shamir.Commitment
}

func (sharing Sharing) N() int { return len(sharing.shares) }

type Row []Sharing

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
