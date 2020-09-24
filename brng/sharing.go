package brng

import "github.com/renproject/shamir"

// A Sharing is a grouping of the shares for a verifiable secret sharing, along
// with the corresponding commitment.
type Sharing struct {
	Shares     shamir.VerifiableShares
	Commitment shamir.Commitment
}
