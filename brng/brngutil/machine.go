package brngutil

import (
	"fmt"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/surge"

	"github.com/renproject/mpc/brng"
	"github.com/renproject/mpc/brng/mock"
	"github.com/renproject/mpc/mpcutil"
)

// PlayerMachine represents one of the players participating in the BRNG
// algorithm.
type PlayerMachine struct {
	id, consID mpcutil.ID
	row        []brng.Sharing

	batchSize uint32
	indices   []secp256k1.Fn
	ownIndex  secp256k1.Fn
	h         secp256k1.Point

	Shares      shamir.VerifiableShares
	Commitments []shamir.Commitment
}

// SizeHint implements the surge.SizeHinter interface.
func (pm PlayerMachine) SizeHint() int {
	return pm.id.SizeHint() +
		pm.consID.SizeHint() +
		surge.SizeHint(pm.row) +
		surge.SizeHint(pm.batchSize) +
		surge.SizeHint(pm.indices) +
		surge.SizeHint(pm.ownIndex) +
		surge.SizeHint(pm.h)
}

// Marshal implements the surge.Marshaler interface.
func (pm PlayerMachine) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := pm.id.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = pm.consID.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(pm.row, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(pm.batchSize, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(pm.indices, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(pm.ownIndex, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return surge.Marshal(pm.h, buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (pm *PlayerMachine) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := pm.id.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = pm.consID.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&pm.row, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&pm.batchSize, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&pm.indices, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&pm.ownIndex, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return surge.Unmarshal(&pm.h, buf, rem)
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
	// TODO: Check validity?
	pm.Shares, pm.Commitments = brng.HandleConsensusOutput(cmsg.sharesBatch, cmsg.commitmentsBatch)
	return nil
}

// ConsensusMachine represents the trusted party for the consensus algorithm
// used by the BRNG algorithm.
type ConsensusMachine struct {
	id        mpcutil.ID
	playerIDs []mpcutil.ID
	indices   []secp256k1.Fn
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
func (cm ConsensusMachine) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := cm.id.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(cm.playerIDs, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(cm.indices, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = cm.engine.Marshal(buf, rem)
	return buf, rem, err
}

// Unmarshal implements the surge.Unmarshaler interface.
func (cm *ConsensusMachine) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := cm.id.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&cm.playerIDs, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&cm.indices, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = cm.engine.Unmarshal(buf, rem)
	return buf, rem, err
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
		done := cm.engine.HandleRow(pmsg.row)
		if done {
			return cm.formConsensusMessages()
		}
		return nil
	}
	return nil
}

func (cm ConsensusMachine) formConsensusMessages() []mpcutil.Message {
	var messages []mpcutil.Message

	table := cm.engine.Table()
	t := len(table)
	b := len(table[0])

	commitmentsBatch := make([][]shamir.Commitment, b)
	for i := range commitmentsBatch {
		commitmentsBatch[i] = make([]shamir.Commitment, t)
		for j := range commitmentsBatch[i] {
			commitmentsBatch[i][j] = table[j][i].Commitment
		}
	}

	for i, id := range cm.playerIDs {
		// index := cm.indices[i]
		sharesBatch := make([]shamir.VerifiableShares, b)

		for j := range sharesBatch {
			sharesBatch[j] = make(shamir.VerifiableShares, t)
			for k := range sharesBatch[j] {
				sharesBatch[j][k] = table[k][j].Shares[i]
			}
		}

		message := BrngMessage{
			msg: &ConsensusMessage{
				from:             cm.id,
				to:               id,
				sharesBatch:      sharesBatch,
				commitmentsBatch: commitmentsBatch,
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
	indices, honestIndices []secp256k1.Fn,
	index secp256k1.Fn,
	h secp256k1.Point,
	k, b int,
) BrngMachine {
	if machineType == BrngTypePlayer {
		row := brng.New(uint32(b), uint32(k), indices, index, h)

		pmachine := PlayerMachine{
			id:          id,
			consID:      consID,
			row:         row,
			batchSize:   uint32(b),
			indices:     indices,
			ownIndex:    index,
			h:           h,
			Shares:      nil,
			Commitments: nil,
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
func (bm BrngMachine) Marshal(buf []byte, rem int) ([]byte, int, error) {
	var ty TypeID
	switch bm.machine.(type) {
	case *PlayerMachine:
		ty = BrngTypePlayer
	case *ConsensusMachine:
		ty = BrngTypeConsensus
	default:
		panic(fmt.Sprintf("unexpected machine type %T", bm.machine))
	}

	buf, rem, err := ty.Marshal(buf, rem)
	if err != nil {
		return buf, rem, fmt.Errorf("error marshaling ty: %v", err)
	}

	return bm.machine.Marshal(buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (bm *BrngMachine) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	var ty TypeID
	buf, rem, err := ty.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}

	switch ty {
	case BrngTypePlayer:
		bm.machine = new(PlayerMachine)
	case BrngTypeConsensus:
		bm.machine = new(ConsensusMachine)
	default:
		return buf, rem, fmt.Errorf("invalid machine type %v", ty)
	}

	return bm.machine.Unmarshal(buf, rem)
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
	return pm.Shares
}

// Commitments returns the output commitments of the player if the machine
// represents a player machine, and nil otherwise.
func (bm BrngMachine) Commitments() []shamir.Commitment {
	pm, ok := bm.machine.(*PlayerMachine)
	if !ok {
		return nil
	}
	return pm.Commitments
}
