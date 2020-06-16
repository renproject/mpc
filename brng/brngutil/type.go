package brngutil

import (
	"io"

	"github.com/renproject/surge"
)

// TypeID is a type alias that represents the different types of messages and
// players that exist.
type TypeID uint8

const (
	// BrngTypePlayer represents the player type that runs the BRNG algorithm.
	BrngTypePlayer = TypeID(1)

	// BrngTypeConsensus represents the consensus trusted party.
	BrngTypeConsensus = TypeID(2)
)

// SizeHint implements the surge.SizeHinter interface.
func (id TypeID) SizeHint() int { return 1 }

// Marshal implements the surge.Marshaler interface.
func (id TypeID) Marshal(w io.Writer, m int) (int, error) {
	return surge.Marshal(w, uint8(id), m)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (id *TypeID) Unmarshal(r io.Reader, m int) (int, error) {
	return surge.Unmarshal(r, (*uint8)(id), m)
}
