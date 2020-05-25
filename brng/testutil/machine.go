package testutil

import (
	"errors"
	"fmt"
	"io"

	"github.com/renproject/mpc/brng"
	"github.com/renproject/mpc/brng/mock"
	"github.com/renproject/secp256k1-go"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/curve"
	"github.com/renproject/surge"

	mtu "github.com/renproject/mpc/testutil"
)

// PlayerMachine represents one of the players participating in the BRNG
// algorithm.
type PlayerMachine struct {
	id, consID mtu.ID
	row        brng.Row
	brnger     brng.BRNGer

	shares      shamir.VerifiableShares
	commitments []shamir.Commitment
}

// SizeHint implements the surge.SizeHinter interface.
func (pm PlayerMachine) SizeHint() int {
	return pm.id.SizeHint() +
		pm.consID.SizeHint() +
		pm.row.SizeHint() +
		pm.brnger.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (pm PlayerMachine) Marshal(w io.Writer, m int) (int, error) {
	m, err := pm.id.Marshal(w, m)
	if err != nil {
		return m, err
	}
	m, err = pm.consID.Marshal(w, m)
	if err != nil {
		return m, err
	}
	m, err = pm.row.Marshal(w, m)
	if err != nil {
		return m, err
	}
	m, err = pm.brnger.Marshal(w, m)
	return m, err
}

// Unmarshal implements the surge.Unmarshaler interface.
func (pm *PlayerMachine) Unmarshal(r io.Reader, m int) (int, error) {
	m, err := pm.id.Unmarshal(r, m)
	if err != nil {
		return m, err
	}
	m, err = pm.consID.Unmarshal(r, m)
	if err != nil {
		return m, err
	}
	m, err = pm.row.Unmarshal(r, m)
	if err != nil {
		return m, err
	}
	m, err = pm.brnger.Unmarshal(r, m)
	return m, err
}

// SetOutput sets the shares and commitments for the player that represent the
// output of the BRNG algorithm.
func (pm *PlayerMachine) SetOutput(shares shamir.VerifiableShares, commitments []shamir.Commitment) {
	pm.shares = shares
	pm.commitments = commitments
}

// ID implements the Machine interface.
func (pm PlayerMachine) ID() mtu.ID {
	return pm.id
}

// Shares returns the output shares of the player.
func (pm PlayerMachine) Shares() shamir.VerifiableShares {
	return pm.shares
}

// Commitments returns the output commitments of the player.
func (pm PlayerMachine) Commitments() []shamir.Commitment {
	return pm.commitments
}

// ConsensusMachine represents the trusted party for the consensus algorithm
// used by the BRNG algorithm.
type ConsensusMachine struct {
	id        mtu.ID
	playerIDs []mtu.ID
	indices   []secp256k1.Secp256k1N
	engine    mock.PullConsensus
}

// ID implements the Machine interface.
func (cm ConsensusMachine) ID() mtu.ID {
	return cm.id
}

// SizeHint implements the surge.SizeHinter interface.
func (cm ConsensusMachine) SizeHint() int {
	return cm.id.SizeHint() +
		surge.SizeHint(cm.playerIDs) +
		surge.SizeHint(cm.indices) +
		cm.engine.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (cm ConsensusMachine) Marshal(w io.Writer, m int) (int, error) {
	m, err := cm.id.Marshal(w, m)
	if err != nil {
		return m, err
	}
	m, err = surge.Marshal(w, cm.playerIDs, m)
	if err != nil {
		return m, err
	}
	m, err = surge.Marshal(w, cm.indices, m)
	if err != nil {
		return m, err
	}
	m, err = cm.engine.Marshal(w, m)
	return m, err
}

// Unmarshal implements the surge.Unmarshaler interface.
func (cm *ConsensusMachine) Unmarshal(r io.Reader, m int) (int, error) {
	m, err := cm.id.Unmarshal(r, m)
	if err != nil {
		return m, err
	}
	m, err = surge.Unmarshal(r, &cm.playerIDs, m)
	if err != nil {
		return m, err
	}
	m, err = surge.Unmarshal(r, &cm.indices, m)
	if err != nil {
		return m, err
	}
	m, err = cm.engine.Unmarshal(r, m)
	return m, err
}

// BrngMachine represents a participant in the BRNG algorithm and can be either
// a player or the consensus trusted party.
type BrngMachine struct {
	machineType TypeID
	n           uint32
	pm          *PlayerMachine
	cm          *ConsensusMachine
}

func NewMachine(
	machineType TypeID,
	id, consID mtu.ID,
	playerIDs []mtu.ID,
	indices, honestIndices []secp256k1.Secp256k1N,
	h curve.Point,
	k, b int,
) BrngMachine {
	if machineType == BrngTypePlayer {
		brnger := brng.New(indices, h)
		row := brnger.TransitionStart(k, b)

		pmachine := PlayerMachine{
			id:          id,
			consID:      consID,
			row:         row,
			brnger:      brnger,
			shares:      nil,
			commitments: nil,
		}

		return BrngMachine{
			machineType: machineType,
			n:           uint32(len(indices)),
			pm:          &pmachine,
			cm:          nil,
		}
	}

	if machineType == BrngTypeConsensus {
		engine := mock.NewPullConsensus(indices, honestIndices, k-1, h)

		cmachine := ConsensusMachine{
			id:        consID,
			playerIDs: playerIDs,
			indices:   indices,
			engine:    engine,
		}

		return BrngMachine{
			machineType: machineType,
			n:           uint32(len(indices)),
			pm:          nil,
			cm:          &cmachine,
		}
	}

	panic("unexpected machine type")
}

// SizeHint implements the surge.SizeHinter interface.
func (bm BrngMachine) SizeHint() int {
	switch bm.machineType {
	case BrngTypePlayer:
		return bm.machineType.SizeHint() + 4 + bm.pm.SizeHint()

	case BrngTypeConsensus:
		return bm.machineType.SizeHint() + 4 + bm.cm.SizeHint()

	default:
		panic("uninitialised machine")
	}
}

// Marshal implements the surge.Marshaler interface.
func (bm BrngMachine) Marshal(w io.Writer, m int) (int, error) {
	m, err := bm.machineType.Marshal(w, m)
	if err != nil {
		return m, err
	}

	m, err = surge.Marshal(w, uint32(bm.n), m)
	if err != nil {
		return m, err
	}

	if bm.pm != nil {
		return bm.pm.Marshal(w, m)
	} else if bm.cm != nil {
		return bm.cm.Marshal(w, m)
	} else {
		return m, errors.New("uninitialised machine")
	}
}

// Unmarshal implements the surge.Unmarshaler interface.
func (bm *BrngMachine) Unmarshal(r io.Reader, m int) (int, error) {
	m, err := bm.machineType.Unmarshal(r, m)
	if err != nil {
		return m, err
	}

	m, err = surge.Unmarshal(r, &bm.n, m)
	if err != nil {
		return m, err
	}

	if bm.machineType == BrngTypePlayer {
		return bm.pm.Unmarshal(r, m)
	} else if bm.machineType == BrngTypeConsensus {
		return bm.cm.Unmarshal(r, m)
	} else {
		return m, fmt.Errorf("invalid message type %v", bm.machineType)
	}
}

// ID implements the Machine interface.
func (bm BrngMachine) ID() mtu.ID {
	if bm.pm != nil {
		return bm.pm.ID()
	} else if bm.cm != nil {
		return bm.cm.ID()
	} else {
		panic("BRNG Machine not initialised")
	}
}

// InitialMessages implements the Machine intercace.
func (bm BrngMachine) InitialMessages() []mtu.Message {
	if bm.machineType == BrngTypePlayer {
		messages := []mtu.Message{
			&BrngMessage{
				msgType: BrngTypePlayer,
				pmsg: &PlayerMessage{
					from: bm.pm.id,
					to:   bm.pm.consID,
					row:  bm.pm.row,
				},
				cmsg: nil,
			},
		}

		return messages
	}

	return nil
}

// Handle implements the Machine interface.
func (bm *BrngMachine) Handle(msg mtu.Message) []mtu.Message {
	bmsg := msg.(*BrngMessage)

	switch bmsg.msgType {
	case BrngTypeConsensus:
		if bmsg.cmsg != nil {
			shares, commitments, _ := bm.pm.brnger.TransitionSlice(bmsg.cmsg.slice)
			bm.pm.SetOutput(shares, commitments)
			return nil
		}
		panic("unexpected consensus message")

	case BrngTypePlayer:
		if bmsg.pmsg != nil {
			// if consensus has not yet been reached
			// handle this row
			// if consensus is reached after handling this row
			// construct the consensus messages for all honest parties
			//
			// if consensus has already been reached
			// then those messages were already constructed and sent
			// so do nothing in this case
			if !bm.cm.engine.Done() {
				done := bm.cm.engine.HandleRow(bmsg.pmsg.Row())
				if done {
					return bm.formConsensusMessages()
				}
				return nil
			}
			return nil
		}
		panic("unexpected player message")

	default:
		panic("unexpected message type")
	}
}

func (bm BrngMachine) formConsensusMessages() []mtu.Message {
	var messages []mtu.Message

	for i, id := range bm.cm.playerIDs {
		index := bm.cm.indices[i]

		message := BrngMessage{
			msgType: BrngTypeConsensus,
			cmsg: &ConsensusMessage{
				from:  bm.cm.id,
				to:    id,
				slice: bm.cm.engine.TakeSlice(index),
			},
			pmsg: nil,
		}

		messages = append(messages, &message)
	}

	return messages
}

// Shares returns the output shares of the player if the machine represents a
// player machine, and nil otherwise.
func (bm BrngMachine) Shares() shamir.VerifiableShares {
	if bm.machineType == BrngTypePlayer {
		if bm.pm != nil {
			return bm.pm.Shares()
		}
	}

	return nil
}

// Commitments returns the output commitments of the player if the machine
// represents a player machine, and nil otherwise.
func (bm BrngMachine) Commitments() []shamir.Commitment {
	if bm.machineType == BrngTypePlayer {
		if bm.pm != nil {
			return bm.pm.Commitments()
		}
	}

	return nil
}
