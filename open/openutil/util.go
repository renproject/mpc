package openutil

import (
	"github.com/renproject/shamir"
)

// GetSharesAt returns the `b` number of shares for an index j < n, where each share
// is the jth share in each set of shares
func GetSharesAt(setsOfShares []shamir.VerifiableShares, j int) shamir.VerifiableShares {
	shares := make(shamir.VerifiableShares, len(setsOfShares))
	for i := 0; i < len(setsOfShares); i++ {
		shares[i] = setsOfShares[i][j]
	}
	return shares
}
