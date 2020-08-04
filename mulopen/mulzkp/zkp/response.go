package zkp

import "github.com/renproject/secp256k1"

// The Response for a challenge in the ZKP.
type Response struct {
	y, w, z, w1, w2 secp256k1.Fn
}
