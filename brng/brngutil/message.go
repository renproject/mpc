package brngutil

import (
	"fmt"

	"github.com/renproject/mpc/brng"
	"github.com/renproject/mpc/mpcutil"
	"github.com/renproject/shamir"
	"github.com/renproject/surge"
)

// PlayerMessage represents a message that a player sends to the consensus
// trusted party in an invocation of the BRNG algorithm.
type PlayerMessage struct {
	from, to mpcutil.ID
	row      []brng.Sharing
}

// From implements the Message interface.
func (pm PlayerMessage) From() mpcutil.ID {
	return pm.from
}

// To implements the Message interface.
func (pm PlayerMessage) To() mpcutil.ID {
	return pm.to
}

// SizeHint implements the surge.SizeHinter interface.
func (pm PlayerMessage) SizeHint() int {
	return pm.from.SizeHint() + pm.to.SizeHint() + surge.SizeHint(pm.row)
}

// Marshal implements the surge.Marshaler interface.
func (pm PlayerMessage) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := pm.from.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = pm.to.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(pm.row, buf, rem)
	return buf, rem, err
}

// Unmarshal implements the surge.Unmarshaler interface.
func (pm *PlayerMessage) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := pm.from.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = pm.to.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&pm.row, buf, rem)
	return buf, rem, err
}

// ConsensusMessage represents the message that the consensus trusted party
// sends to all of the parties once consensus has been reached in the BRNG
// algorithm.
type ConsensusMessage struct {
	from, to         mpcutil.ID
	sharesBatch      []shamir.VerifiableShares
	commitmentsBatch [][]shamir.Commitment
}

// From implements the Message interface.
func (cm ConsensusMessage) From() mpcutil.ID {
	return cm.from
}

// To implements the Message interface.
func (cm ConsensusMessage) To() mpcutil.ID {
	return cm.to
}

// SizeHint implements the surge.SizeHinter interface.
func (cm ConsensusMessage) SizeHint() int {
	return cm.from.SizeHint() +
		cm.to.SizeHint() +
		surge.SizeHint(cm.sharesBatch) +
		surge.SizeHint(cm.commitmentsBatch)
}

// Marshal implements the surge.Marshaler interface.
func (cm ConsensusMessage) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := cm.from.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = cm.to.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(cm.sharesBatch, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return surge.Marshal(cm.commitmentsBatch, buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (cm *ConsensusMessage) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := cm.from.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = cm.to.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&cm.sharesBatch, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return surge.Unmarshal(&cm.commitmentsBatch, buf, rem)
}

// BrngMessage is a wrapper for any of the messages that can be sent during an
// invocation of the BRNG algorithm.
type BrngMessage struct {
	msg mpcutil.Message
}

// From implements the Message interface.
func (bm BrngMessage) From() mpcutil.ID {
	return bm.msg.From()
}

// To implements the Message interface.
func (bm BrngMessage) To() mpcutil.ID {
	return bm.msg.To()
}

// SizeHint implements the surge.SizeHinter interface.
func (bm BrngMessage) SizeHint() int {
	return 1 + bm.msg.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (bm BrngMessage) Marshal(buf []byte, rem int) ([]byte, int, error) {
	var ty TypeID
	switch bm.msg.(type) {
	case *PlayerMessage:
		ty = BrngTypePlayer
	case *ConsensusMessage:
		ty = BrngTypeConsensus
	default:
		panic(fmt.Sprintf("unexpected message type %T", bm.msg))
	}

	buf, rem, err := ty.Marshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("error marshaling ty: %v", err)
	}

	return bm.msg.Marshal(buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (bm *BrngMessage) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	var ty TypeID
	buf, rem, err := ty.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}

	switch ty {
	case BrngTypePlayer:
		bm.msg = new(PlayerMessage)
	case BrngTypeConsensus:
		bm.msg = new(ConsensusMessage)
	default:
		return buf, rem, fmt.Errorf("invalid message type %v", ty)
	}

	return bm.msg.Unmarshal(buf, rem)
}
