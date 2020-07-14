package brngutil

import (
	"fmt"
	"io"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/curve"
	"github.com/renproject/surge"

	"github.com/renproject/mpc/brng"
	"github.com/renproject/mpc/brng/mock"
	"github.com/renproject/mpc/brng/table"
	"github.com/renproject/mpc/mpcutil"
)

// PlayerMachine represents one of the players participating in the BRNG
// algorithm.
type PlayerMachine struct {
	id, consID mpcutil.ID
	row        table.Row
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

// ID implements the Machine interface.
func (pm PlayerMachine) ID() mpcutil.ID {
	return pm.id
}

// InitialMessages implements the Machine intercace.
func (pm PlayerMachine) InitialMessages() []mpcutil.Message {
	return []mpcutil.Message{
		&BrngMessage{
			msg: &PlayerMessage{
				from: pm.id,
				to:   pm.consID,
				row:  pm.row,
			},
		},
	}
}

// Handle implements the Machine interface.
func (pm *PlayerMachine) Handle(msg mpcutil.Message) []mpcutil.Message {
	cmsg := msg.(*ConsensusMessage)
	shares, commitments, _ := pm.brnger.TransitionSlice(cmsg.slice)
	pm.SetOutput(shares, commitments)
	return nil
}

// SetOutput sets the shares and commitments for the player that represent the
// output of the BRNG algorithm.
func (pm *PlayerMachine) SetOutput(shares shamir.VerifiableShares, commitments []shamir.Commitment) {
	pm.shares = shares
	pm.commitments = commitments
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
	id        mpcutil.ID
	playerIDs []mpcutil.ID
	indices   []secp256k1.Secp256k1N
	engine    mock.PullConsensus
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

// ID implements the Machine interface.
func (cm ConsensusMachine) ID() mpcutil.ID {
	return cm.id
}

// InitialMessages implements the Machine intercace.
func (cm ConsensusMachine) InitialMessages() []mpcutil.Message {
	return nil
}

// Handle implements the Machine interface.
func (cm *ConsensusMachine) Handle(msg mpcutil.Message) []mpcutil.Message {
	pmsg := msg.(*PlayerMessage)

	// if consensus has not yet been reached
	// handle this row
	// if consensus is reached after handling this row
	// construct the consensus messages for all honest parties
	//
	// if consensus has already been reached
	// then those messages were already constructed and sent
	// so do nothing in this case
	if !cm.engine.Done() {
		done := cm.engine.HandleRow(pmsg.Row())
		if done {
			return cm.formConsensusMessages()
		}
		return nil
	}
	return nil
}

func (cm ConsensusMachine) formConsensusMessages() []mpcutil.Message {
	var messages []mpcutil.Message

	for i, id := range cm.playerIDs {
		index := cm.indices[i]

		message := BrngMessage{
			msg: &ConsensusMessage{
				from:  cm.id,
				to:    id,
				slice: cm.engine.TakeSlice(index),
			},
		}

		messages = append(messages, &message)
	}

	return messages
}

// BrngMachine represents a participant in the BRNG algorithm and can be either
// a player or the consensus trusted party.
type BrngMachine struct {
	machine mpcutil.Machine
}

// NewMachine constructs a new machine for the BRNG algorithm tests. The
// machine can represent either a player or the consensus trusted party, and
// this is determined by the machineType argument. The machine will have an ID
// given by the id argument, and the ID of the consensus trusted party is
// consID. The IDs of all of the players in network is playerIDs. The
// corresponding Shamir indices is given by the indices argument. The
// honestIndices argument is the list of those indices for which the players
// are honest; neither offline nor malicious. h is the Pedersen parameter, k is
// the Shamir threshold and b is the batch size.
func NewMachine(
	machineType TypeID,
	id, consID mpcutil.ID,
	playerIDs []mpcutil.ID,
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
			machine: &pmachine,
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
			machine: &cmachine,
		}
	}

	panic("unexpected machine type")
}

// SizeHint implements the surge.SizeHinter interface.
func (bm BrngMachine) SizeHint() int {
	return 1 + bm.machine.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (bm BrngMachine) Marshal(w io.Writer, m int) (int, error) {
	var ty TypeID
	switch bm.machine.(type) {
	case *PlayerMachine:
		ty = BrngTypePlayer
	case *ConsensusMachine:
		ty = BrngTypeConsensus
	default:
		panic(fmt.Sprintf("unexpected machine type %T", bm.machine))
	}

	m, err := ty.Marshal(w, m)
	if err != nil {
		return m, fmt.Errorf("error marshaling ty: %v", err)
	}

	return bm.machine.Marshal(w, m)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (bm *BrngMachine) Unmarshal(r io.Reader, m int) (int, error) {
	var ty TypeID
	m, err := ty.Unmarshal(r, m)
	if err != nil {
		return m, err
	}

	switch ty {
	case BrngTypePlayer:
		bm.machine = new(PlayerMachine)
	case BrngTypeConsensus:
		bm.machine = new(ConsensusMachine)
	default:
		return m, fmt.Errorf("invalid machine type %v", ty)
	}

	return bm.machine.Unmarshal(r, m)
}

// ID implements the Machine interface.
func (bm BrngMachine) ID() mpcutil.ID {
	return bm.machine.ID()
}

// InitialMessages implements the Machine intercace.
func (bm BrngMachine) InitialMessages() []mpcutil.Message {
	return bm.machine.InitialMessages()
}

// Handle implements the Machine interface.
func (bm *BrngMachine) Handle(msg mpcutil.Message) []mpcutil.Message {
	bmsg := msg.(*BrngMessage)

	switch msg := bmsg.msg.(type) {
	case *PlayerMessage, *ConsensusMessage:
		return bm.machine.Handle(msg)
	default:
		panic(fmt.Sprintf("unexpected message type %T", msg))
	}
}

// Shares returns the output shares of the player if the machine represents a
// player machine, and nil otherwise.
func (bm BrngMachine) Shares() shamir.VerifiableShares {
	pm, ok := bm.machine.(*PlayerMachine)
	if !ok {
		return nil
	}
	return pm.Shares()
}

// Commitments returns the output commitments of the player if the machine
// represents a player machine, and nil otherwise.
func (bm BrngMachine) Commitments() []shamir.Commitment {
	pm, ok := bm.machine.(*PlayerMachine)
	if !ok {
		return nil
	}
	return pm.Commitments()
}
