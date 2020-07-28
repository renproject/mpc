package open

import "errors"

var (
	// ErrDuplicateIndex signifies that the received share has an index that is
	// the same as the index of one of the shares that is already in the list
	// of valid shares received for the current sharing instance. This can be
	// output in both the Waiting and Done states.
	ErrDuplicateIndex = errors.New("duplicate index")

	// ErrIndexOutOfRange signifies that the received share has an index that
	// is not in the set of indices that the state machine was constructed
	// with.  This can be output in both the Waiting and Done states.
	ErrIndexOutOfRange = errors.New("index out of range")

	// ErrInvalidShares signifies that at least one out of the received shares
	// is not valid with respect to the commitment for the current sharing
	// instance. This can be output in both the Waiting and Done states.
	ErrInvalidShares = errors.New("invalid shares")

	// ErrIncorrectBatchSize signifies that the batch size of the received
	// shares is different to that specified by the opener instance.
	ErrIncorrectBatchSize = errors.New("incorrect batch size")
)
