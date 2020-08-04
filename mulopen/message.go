package mulopen

import (
	"github.com/renproject/mpc/mulopen/mulzkp"
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
)

type Message struct {
	VShare     shamir.VerifiableShare
	Commitment secp256k1.Point
	Proof      mulzkp.Proof
}
