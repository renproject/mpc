package brngutil

import (
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
func (id TypeID) Marshal(buf []byte, rem int) ([]byte, int, error) {
	return surge.MarshalU8(uint8(id), buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (id *TypeID) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	return surge.UnmarshalU8((*uint8)(id), buf, rem)
}
