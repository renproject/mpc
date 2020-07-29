package rkpg

import "errors"

var (
	ErrWrongBatchSize     = errors.New("wrong batch size")
	ErrInvalidIndex       = errors.New("invalid index")
	ErrDuplicateIndex     = errors.New("duplicate index")
	ErrInconsistentShares = errors.New("inconsistent shares")
	ErrTooManyErrors      = errors.New("too many errors")
)
