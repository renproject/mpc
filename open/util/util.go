package util

import (
  "github.com/renproject/shamir"
)

func GetSharesAt(setsOfShares []shamir.VerifiableShares, b, j int) shamir.VerifiableShares {
  shares := make(shamir.VerifiableShares, b)
  for i := 0; i < b; i++ {
    shares[i] = setsOfShares[i][j]
  }
  return shares
}
