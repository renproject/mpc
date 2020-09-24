package mulopen

import "errors"

var (
	// ErrIncorrectBatchSize is returned when the batch size of the given
	// message is not equal to the batch size of the multiply and open
	// instance.
	ErrIncorrectBatchSize = errors.New("incorrect batch size")

	// ErrInvalidIndex is returned when the index of the shares in the batch
	// are not in the index set for the RKPG instance.
	ErrInvalidIndex = errors.New("invalid index")

	// ErrInconsistentShares is returned when not all shares in the batch have
	// the same index.
	ErrInconsistentShares = errors.New("inconsistent shares")

	// ErrDuplicateIndex signifies that the received share has an index that is
	// the same as the index of one of the shares that is already in the list
	// of valid shares received for the current sharing instance.
	ErrDuplicateIndex = errors.New("duplicate index")

	// ErrInvalidZKP is returned when not all of the given ZKPs in the message
	// are valid.
	ErrInvalidZKP = errors.New("invalid zkp")

	// ErrInvalidShares is returned when not all of the given shares are valid
	// with respect to their corresponding commitments.
	ErrInvalidShares = errors.New("invalid shares")
)
