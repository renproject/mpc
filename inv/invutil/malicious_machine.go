package invutil

import (
	"math/rand"

	"github.com/renproject/mpc/inv"
	"github.com/renproject/mpc/mpcutil"
	"github.com/renproject/mpc/mulopen"
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/shamirutil"
	"github.com/renproject/surge"
)

// MaliciousMachine represents a player that deviates from the inversion
// protocol by sending invalid messages.
type MaliciousMachine struct {
	OwnID    mpcutil.ID
	InitMsgs []Message
}

// NewMaliciousMachine constructs a new malicious machine for an inversion
// network test. It will have the given inputs and ID.
func NewMaliciousMachine(
	aShareBatch, bShareBatch, rzgShareBatch shamir.VerifiableShares,
	aCommitmentBatch, bCommitmentBatch, rzgCommitmentBatch []shamir.Commitment,
	ids []mpcutil.ID, ownID mpcutil.ID, indices []secp256k1.Fn, h secp256k1.Point,
) MaliciousMachine {
	_, msgs := inv.New(
		aShareBatch, bShareBatch, rzgShareBatch,
		aCommitmentBatch, bCommitmentBatch, rzgCommitmentBatch,
		indices, h,
	)
	toBeModified := randomIDSubset(ids)
	initialMessages := make([]Message, 0, len(ids)-1)
	for _, id := range ids {
		if id == ownID {
			continue
		}
		msgsCopy := make([]mulopen.Message, len(msgs))
		copy(msgsCopy, msgs)
		message := Message{
			FromID:   ownID,
			ToID:     id,
			Messages: msgsCopy,
		}
		if _, ok := toBeModified[id]; ok {
			modifyMessageBatch(message.Messages)
		}
		initialMessages = append(initialMessages, message)
	}
	return MaliciousMachine{
		OwnID:    ownID,
		InitMsgs: initialMessages,
	}
}

func randomIDSubset(ids []mpcutil.ID) map[mpcutil.ID]struct{} {
	shuffledIDs := make([]mpcutil.ID, len(ids))
	copy(shuffledIDs, ids)
	rand.Shuffle(len(shuffledIDs), func(i, j int) {
		shuffledIDs[i], shuffledIDs[j] = shuffledIDs[j], shuffledIDs[i]
	})
	numModified := shamirutil.RandRange(1, len(ids)-1)
	isInSubset := make(map[mpcutil.ID]struct{}, numModified)
	for i := 0; i < numModified; i++ {
		isInSubset[shuffledIDs[i]] = struct{}{}
	}
	return isInSubset
}

func modifyMessageBatch(messageBatch []mulopen.Message) {
	batchToModify := rand.Intn(len(messageBatch))
	switch rand.Intn(3) {
	case 0:
		messageBatch[batchToModify].VShare.Share.Value = secp256k1.RandomFn()
	case 1:
		messageBatch[batchToModify].VShare.Decommitment = secp256k1.RandomFn()
	case 2:
		messageBatch[batchToModify].Commitment = secp256k1.RandomPoint()
	default:
		panic("invalid case")
	}
}

// ID implements the Machine interface.
func (m MaliciousMachine) ID() mpcutil.ID { return m.OwnID }

// InitialMessages implements the Machine interface.
func (m MaliciousMachine) InitialMessages() []mpcutil.Message {
	msgs := make([]mpcutil.Message, len(m.InitMsgs))
	for i := range m.InitMsgs {
		msgs[i] = &m.InitMsgs[i]
	}
	return msgs
}

// Handle implements the Machine interface.
func (m *MaliciousMachine) Handle(msg mpcutil.Message) []mpcutil.Message {
	return nil
}

// SizeHint implements the surge.SizeHinter interface.
func (m MaliciousMachine) SizeHint() int {
	return m.OwnID.SizeHint() +
		surge.SizeHint(m.InitMsgs)
}

// Marshal implements the surge.Marshaler interface.
func (m MaliciousMachine) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := m.OwnID.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return surge.Marshal(m.InitMsgs, buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (m *MaliciousMachine) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := m.OwnID.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return surge.Unmarshal(&m.InitMsgs, buf, rem)
}
