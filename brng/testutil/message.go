package testutil

import (
	"errors"
	"fmt"
	"io"

	"github.com/renproject/mpc/brng"
	mtu "github.com/renproject/mpc/testutil"
)

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

type BrngMessage struct {
	msgType TypeID
	pmsg    *PlayerMessage
	cmsg    *ConsensusMessage
}

// From implements the Message interface.
func (bm BrngMessage) From() mtu.ID {
	if bm.pmsg != nil {
		return bm.pmsg.From()
	} else if bm.cmsg != nil {
		return bm.cmsg.From()
	} else {
		panic("BRNG Message not initialised")
	}
}

// To implements the Message interface.
func (bm BrngMessage) To() mtu.ID {
	if bm.pmsg != nil {
		return bm.pmsg.To()
	} else if bm.cmsg != nil {
		return bm.cmsg.To()
	} else {
		panic("BRNG Message not initialised")
	}
}

// SizeHint implements the surge.SizeHinter interface.
func (bm BrngMessage) SizeHint() int {
	switch bm.msgType {
	case BrngTypePlayer:
		return bm.msgType.SizeHint() + bm.pmsg.SizeHint()

	case BrngTypeConsensus:
		return bm.msgType.SizeHint() + bm.cmsg.SizeHint()

	default:
		panic("uninitialised message")
	}
}

// Marshal implements the surge.Marshaler interface.
func (bm BrngMessage) Marshal(w io.Writer, m int) (int, error) {
	m, err := bm.msgType.Marshal(w, m)
	if err != nil {
		return m, err
	}

	if bm.pmsg != nil {
		return bm.pmsg.Marshal(w, m)
	} else if bm.cmsg != nil {
		return bm.cmsg.Marshal(w, m)
	} else {
		return m, errors.New("uninitialised message")
	}
}

// Unmarshal implements the surge.Unmarshaler interface.
func (bm *BrngMessage) Unmarshal(r io.Reader, m int) (int, error) {
	m, err := bm.msgType.Unmarshal(r, m)
	if err != nil {
		return m, err
	}

	if bm.msgType == BrngTypePlayer {
		return bm.pmsg.Unmarshal(r, m)
	} else if bm.msgType == BrngTypeConsensus {
		return bm.cmsg.Unmarshal(r, m)
	} else {
		return m, fmt.Errorf("invalid message type %v", bm.msgType)
	}
}
