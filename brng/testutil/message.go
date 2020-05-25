package testutil

import (
	"fmt"
	"io"

	"github.com/renproject/mpc/brng"
	mtu "github.com/renproject/mpc/testutil"
)

// PlayerMessage represents a message that a player sends to the consensus
// trusted party in an invocation of the BRNG algorithm.
type PlayerMessage struct {
	from, to mtu.ID
	row      brng.Row
}

// From implements the Message interface.
func (pm PlayerMessage) From() mtu.ID {
	return pm.from
}

// To implements the Message interface.
func (pm PlayerMessage) To() mtu.ID {
	return pm.to
}

// Row returns the row that the message contains.
func (pm PlayerMessage) Row() brng.Row {
	return pm.row
}

// SizeHint implements the surge.SizeHinter interface.
func (pm PlayerMessage) SizeHint() int {
	return pm.from.SizeHint() + pm.to.SizeHint() + pm.row.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (pm PlayerMessage) Marshal(w io.Writer, m int) (int, error) {
	m, err := pm.from.Marshal(w, m)
	if err != nil {
		return m, err
	}
	m, err = pm.to.Marshal(w, m)
	if err != nil {
		return m, err
	}
	m, err = pm.row.Marshal(w, m)
	return m, err
}

// Unmarshal implements the surge.Unmarshaler interface.
func (pm *PlayerMessage) Unmarshal(r io.Reader, m int) (int, error) {
	m, err := pm.from.Unmarshal(r, m)
	if err != nil {
		return m, err
	}
	m, err = pm.to.Unmarshal(r, m)
	if err != nil {
		return m, err
	}
	m, err = pm.row.Unmarshal(r, m)
	return m, err
}

// ConsensusMessage represents the message that the consensus trusted party
// sends to all of the parties once consensus has been reached in the BRNG
// algorithm.
type ConsensusMessage struct {
	from, to mtu.ID
	slice    brng.Slice
}

// From implements the Message interface.
func (cm ConsensusMessage) From() mtu.ID {
	return cm.from
}

// To implements the Message interface.
func (cm ConsensusMessage) To() mtu.ID {
	return cm.to
}

// SizeHint implements the surge.SizeHinter interface.
func (cm ConsensusMessage) SizeHint() int {
	return cm.from.SizeHint() + cm.to.SizeHint() + cm.slice.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (cm ConsensusMessage) Marshal(w io.Writer, m int) (int, error) {
	m, err := cm.from.Marshal(w, m)
	if err != nil {
		return m, err
	}
	m, err = cm.to.Marshal(w, m)
	if err != nil {
		return m, err
	}
	m, err = cm.slice.Marshal(w, m)
	return m, err
}

// Unmarshal implements the surge.Unmarshaler interface.
func (cm *ConsensusMessage) Unmarshal(r io.Reader, m int) (int, error) {
	m, err := cm.from.Unmarshal(r, m)
	if err != nil {
		return m, err
	}
	m, err = cm.to.Unmarshal(r, m)
	if err != nil {
		return m, err
	}
	m, err = cm.slice.Unmarshal(r, m)
	return m, err
}

// BrngMessage is a wrapper for any of the messages that can be sent during an
// invocation of the BRNG algorithm.
type BrngMessage struct {
	msg mtu.Message
}

// From implements the Message interface.
func (bm BrngMessage) From() mtu.ID {
	return bm.msg.From()
}

// To implements the Message interface.
func (bm BrngMessage) To() mtu.ID {
	return bm.msg.To()
}

// SizeHint implements the surge.SizeHinter interface.
func (bm BrngMessage) SizeHint() int {
	return 1 + bm.msg.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (bm BrngMessage) Marshal(w io.Writer, m int) (int, error) {
	var ty TypeID
	switch bm.msg.(type) {
	case *PlayerMessage:
		ty = BrngTypePlayer
	case *ConsensusMessage:
		ty = BrngTypeConsensus
	default:
		panic(fmt.Sprintf("unexpected message type %T", bm.msg))
	}

	m, err := ty.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("error marshaling ty: %v", err)
	}

	return bm.msg.Marshal(w, m)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (bm *BrngMessage) Unmarshal(r io.Reader, m int) (int, error) {
	var ty TypeID
	m, err := ty.Unmarshal(r, m)
	if err != nil {
		return m, err
	}

	switch ty {
	case BrngTypePlayer:
		bm.msg = new(PlayerMessage)
	case BrngTypeConsensus:
		bm.msg = new(ConsensusMessage)
	default:
		return m, fmt.Errorf("invalid message type %v", ty)
	}

	return bm.msg.Unmarshal(r, m)
}
