package zkp

import "github.com/renproject/secp256k1"

// The Witness for the ZKP.
type Witness struct {
	d, s, x, s1, s2              secp256k1.Fn
	alpha, beta, rho, sigma, tau secp256k1.Fn
}
