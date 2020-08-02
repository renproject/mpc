package brng

import "errors"

var (
	ErrIncorrectBatchSize     = errors.New("incorrect batch size")
	ErrInvalidInputDimensions = errors.New("invalid input dimensions")
	ErrInvalidShares          = errors.New("invalid shares")
	ErrIncorrectIndex         = errors.New("incorrect index")
	ErrNotEnoughContributions = errors.New("not enough contributions")
)
