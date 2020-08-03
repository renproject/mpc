package rkpg

import "errors"

var (
	// ErrWrongBatchSize is returned when the batch size of the given shares is
	// not equal to the batch size for the RKPG instance.
	ErrWrongBatchSize = errors.New("wrong batch size")

	// ErrInvalidIndex is returned when the index of the shares in the batch
	// are not in the index set for the RKPG instance.
	ErrInvalidIndex = errors.New("invalid index")

	// ErrDuplicateIndex is returned when the index of the shares in the batch
	// has already been seen before.
	ErrDuplicateIndex = errors.New("duplicate index")

	// ErrInconsistentShares is returned when not all shares in the batch have
	// the same index.
	ErrInconsistentShares = errors.New("inconsistent shares")

	// ErrTooManyErrors is returned when during a reconstruction attempt using
	// RS decoding, there were too many errant shares to obtain a result.
	ErrTooManyErrors = errors.New("too many errors")
)
