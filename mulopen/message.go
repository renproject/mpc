package mulopen

import (
	"github.com/renproject/mpc/mulopen/mulzkp"
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
)

// The Message type that is sent between parties during an invocation of
// multiply and open.
type Message struct {
	VShare     shamir.VerifiableShare
	Commitment secp256k1.Point
	Proof      mulzkp.Proof
}
