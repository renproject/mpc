package table

import (
	"github.com/renproject/shamir"
	"github.com/renproject/surge"
)

// A Col is a slice of Elements, and represents all of the shares that
// correspond to a single global random number.
type Col []Element

// SizeHint implements the surge.SizeHinter interface.
func (col Col) SizeHint() int { return surge.SizeHint([]Element(col)) }

// Marshal implements the surge.Marshaler interface.
func (col Col) Marshal(buf []byte, rem int) ([]byte, int, error) {
	return surge.Marshal([]Element(col), buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (col *Col) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	return surge.Unmarshal((*[]Element)(col), buf, rem)
}

// Sum returns the share and Pedersen commitment that corresponds to the sum of
// the verifiable shares of the Elements in the Col.
func (col Col) Sum() (shamir.VerifiableShare, shamir.Commitment) {
	var share shamir.VerifiableShare
	var commitment shamir.Commitment

	if len(col) == 0 {
		return share, commitment
	}

	share = col[0].Share()
	commitment.Set(col[0].Commitment())

	for i := 1; i < len(col); i++ {
		share.Add(&share, &col[i].share)
		commitment.Add(commitment, col[i].commitment)
	}

	return share, commitment
}

func (col Col) ShareSum() shamir.VerifiableShare {
	var share shamir.VerifiableShare
	if len(col) == 0 {
		return share
	}
	share = col[0].Share()
	for i := 1; i < len(col); i++ {
		share.Add(&share, &col[i].share)
	}
	return share
}

func (col Col) CommitmentSum() shamir.Commitment {
	var commitment shamir.Commitment
	if len(col) == 0 {
		return commitment
	}
	commitment.Set(col[0].Commitment())
	for i := 1; i < len(col); i++ {
		commitment.Add(commitment, col[i].commitment)
	}
	return commitment
}
