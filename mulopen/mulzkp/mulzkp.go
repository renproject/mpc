// Package mulzkp provides an implementation of the ZKP for the multiplication
// of Pedersen commited values described in Appendix C of [1], augmented to be
// non interactive by using the Fiat Shamir transform.
//
// [1] Rosario Gennaro, Michael O. Rabin, and Tal Rabin. 1998.
// Simplified VSS and fast-track multiparty computations with applications to
// threshold cryptography.
// In Proceedings of the seventeenth annual ACM symposium on Principles of
// distributed computing (PODC ’98). Association for Computing Machinery, New
// York, NY, USA, 101–111.
// https://doi.org/10.1145/277697.277716
package mulzkp

import (
	"crypto/sha256"

	"github.com/renproject/mpc/mulopen/mulzkp/zkp"
	"github.com/renproject/secp256k1"
)

// CreateProof constructs a new ZKP that attests to the fact that
// 		c = (alpha*beta)G + (tau)H,
// where
//		a = (alpha)G + (rho)H, and
//		b = (beta)G + (sigma)H.
func CreateProof(h, a, b, c *secp256k1.Point, alpha, beta, rho, sigma, tau secp256k1.Fn) Proof {
	msg, w := zkp.New(h, b, alpha, beta, rho, sigma, tau)
	e := computeChallenge(a, b, c, &msg)
	res := zkp.ResponseForChallenge(&w, &e)

	return Proof{msg, res}
}

// Verify the given proof. The return value will be true if
// 		c = (alpha*beta)G + (tau)H,
// where
//		a = (alpha)G + (rho)H, and
//		b = (beta)G + (sigma)H
// for some alpha, beta, rho, sigma, tau. Otherwise, the return value will be
// false.
func Verify(h, a, b, c *secp256k1.Point, p *Proof) bool {
	e := computeChallenge(a, b, c, &p.msg)
	return zkp.Verify(h, a, b, c, &p.msg, &p.res, &e)
}

func computeChallenge(a, b, c *secp256k1.Point, msg *zkp.Message) secp256k1.Fn {
	l := a.SizeHint() + b.SizeHint() + c.SizeHint() + msg.SizeHint()
	buf := make([]byte, l)

	var tail []byte
	rem := l
	var err error

	tail, rem, err = a.Marshal(buf, rem)
	if err != nil {
		panic("unreachable")
	}
	tail, rem, err = b.Marshal(tail, rem)
	if err != nil {
		panic("unreachable")
	}
	tail, rem, err = c.Marshal(tail, rem)
	if err != nil {
		panic("unreachable")
	}
	tail, rem, err = msg.Marshal(tail, rem)
	if err != nil {
		panic("unreachable")
	}
	hash := sha256.Sum256(buf)

	var e secp256k1.Fn
	_ = e.SetB32(hash[:])
	return e
}
