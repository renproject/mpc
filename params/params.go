package params

import "github.com/renproject/secp256k1"

// ValiValidPedersenParameter returns false when the given curve point cannot
// be securely used as a Pedersen commitment scheme parameter. This function
// does NOT guarantee that the Pedersen parameter is secure, but simply checks
// a small number of basic cases that are known to be insecure.
func ValidPedersenParameter(h secp256k1.Point) bool {
	var g secp256k1.Point
	one := secp256k1.NewFnFromU16(1)
	g.BaseExp(&one)
	return !h.IsInfinity() && !h.Eq(&g)
}
