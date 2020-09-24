package brng

import "errors"

var (
	// ErrIncorrectCommitmentsBatchSize is returned when the batch size of the
	// given commitments is not equal to the batch size of the BRNGer.
	ErrIncorrectCommitmentsBatchSize = errors.New("incorrect commitments batch size")

	// ErrIncorrectSharesBatchSize is returned when the batch size of the given
	// shares is not equal to the batch size of the BRNGer.
	ErrIncorrectSharesBatchSize = errors.New("incorrect shares batch size")

	// ErrInvalidCommitmentDimensions is returned when the batch of commitments
	// has inconsistent dimensions. This can occur when not all slices in the
	// batch have the same length (this length is equal to the number of
	// contributions for the batch), or when not all commitments have the same
	// threshold.
	ErrInvalidCommitmentDimensions = errors.New("invalid commitment dimensions")

	// ErrInvalidShareDimensions is returned when the batch of shares has
	// inconsistent dimensions. This occurs when not all slices in the batch
	// have the same length (this length is equal to the number of
	// contributions for the batch).
	ErrInvalidShareDimensions = errors.New("invalid share dimensions")

	// ErrInvalidShares is returned when not all of the given shares are valid
	// with respect to their corresponding commitments.
	ErrInvalidShares = errors.New("invalid shares")

	// ErrIncorrectIndex is returned when not all of the shares have index
	// equal to the index for the BRNGer.
	ErrIncorrectIndex = errors.New("incorrect index")

	// ErrNotEnoughContributions is returned when the number of contributions
	// from other players is smaller than the number of required contributions.
	ErrNotEnoughContributions = errors.New("not enough contributions")
)
