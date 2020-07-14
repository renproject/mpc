package table

import (
	"io"

	"github.com/renproject/shamir"
	"github.com/renproject/shamir/shamirutil"
	"github.com/renproject/surge"
)

// A Col is a slice of Elements, and represents all of the shares that
// correspond to a single global random number.
type Col []Element

// SizeHint implements the surge.SizeHinter interface.
func (col Col) SizeHint() int { return surge.SizeHint([]Element(col)) }

// Marshal implements the surge.Marshaler interface.
func (col Col) Marshal(w io.Writer, m int) (int, error) {
	return surge.Marshal(w, []Element(col), m)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (col *Col) Unmarshal(r io.Reader, m int) (int, error) {
	var l uint32
	m, err := shamirutil.UnmarshalSliceLen32(&l, shamir.FnSizeBytes, r, m)
	if err != nil {
		return m, err
	}

	*col = (*col)[:0]
	for i := uint32(0); i < l; i++ {
		*col = append(*col, Element{})
		m, err = (*col)[i].Unmarshal(r, m)
		if err != nil {
			return m, err
		}
	}

	return m, nil
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
