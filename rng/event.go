package rng

import "errors"

var (
	// ErrSharesIgnored represents the event returned when the RNG state machine
	// received `b` sets of verifiable shares that were invalid in some way
	ErrSharesIgnored = errors.New("shares ignored")
)
