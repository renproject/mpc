package brng

import "github.com/renproject/shamir"

type Sharing struct {
	Shares     shamir.VerifiableShares
	Commitment shamir.Commitment
}
