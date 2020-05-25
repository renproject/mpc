package table

import (
	"io"

	"github.com/renproject/shamir"
	"github.com/renproject/surge"
)

// A Slice represents a batch of Cols, which corresponds to the batch number of
// global random numbers for the BRNG algorithm.
type Slice []Col

// SizeHint implements the surge.SizeHinter interface.
func (slice Slice) SizeHint() int { return surge.SizeHint([]Col(slice)) }

// Marshal implements the surge.Marshaler interface.
func (slice Slice) Marshal(w io.Writer, m int) (int, error) {
	return surge.Marshal(w, []Col(slice), m)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (slice *Slice) Unmarshal(r io.Reader, m int) (int, error) {
	return surge.Unmarshal(r, (*[]Col)(slice), m)
}

// BatchSize returns the number of Cols in the slice, which is equal to the
// batch size.
func (slice Slice) BatchSize() int {
	return len(slice)
}

// HasValidForm returns true
func (slice Slice) HasValidForm() bool {
	if slice.BatchSize() == 0 {
		return false
	}

	colLen := len(slice[0])

	for i := 1; i < len(slice); i++ {
		if len(slice[i]) != colLen {
			return false
		}
	}

	return true
}

// Faults returns a list of faults (if any) that exist in the given slice.
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