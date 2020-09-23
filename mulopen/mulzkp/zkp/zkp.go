// Package zkp provides an implementation of the ZKP for the multiplication of
// Pedersen commited values described in Appendix C of [1].
//
// [1] Rosario Gennaro, Michael O. Rabin, and Tal Rabin. 1998.
// Simplified VSS and fast-track multiparty computations with applications to
// threshold cryptography.
// In Proceedings of the seventeenth annual ACM symposium on Principles of
// distributed computing (PODC ’98). Association for Computing Machinery, New
// York, NY, USA, 101–111.
// https://doi.org/10.1145/277697.277716
package zkp

import "github.com/renproject/secp256k1"

// New constructs a new message and witness for the ZKP for the given
// parameters.
func New(h, b *secp256k1.Point, alpha, beta, rho, sigma, tau secp256k1.Fn) (Message, Witness) {
	msg := Message{}
	w := Witness{
		d:  secp256k1.RandomFn(),
		s:  secp256k1.RandomFn(),
		x:  secp256k1.RandomFn(),
		s1: secp256k1.RandomFn(),
		s2: secp256k1.RandomFn(),

		alpha: alpha,
		beta:  beta,
		rho:   rho,
		sigma: sigma,
		tau:   tau,
	}

	var hPow secp256k1.Point

	hPow.Scale(h, &w.s)
	msg.m.BaseExp(&w.d)
	msg.m.Add(&msg.m, &hPow)

	hPow.Scale(h, &w.s1)
	msg.m1.BaseExp(&w.x)
	msg.m1.Add(&msg.m1, &hPow)

	hPow.Scale(h, &w.s2)
	msg.m2.Scale(b, &w.x)
	msg.m2.Add(&msg.m2, &hPow)

	return msg, w
}

// ResponseForChallenge constructs a valid response for the given challenge and
// witness.
func ResponseForChallenge(w *Witness, e *secp256k1.Fn) Response {
	var res Response

	res.y.Mul(e, &w.beta)
	res.y.Add(&res.y, &w.d)

	res.w.Mul(e, &w.sigma)
	res.w.Add(&res.w, &w.s)

	res.z.Mul(e, &w.alpha)
	res.z.Add(&res.z, &w.x)

	res.w1.Mul(e, &w.rho)
	res.w1.Add(&res.w1, &w.s1)

	res.w2.Mul(&w.sigma, &w.alpha)
	res.w2.Negate(&res.w2)
	res.w2.Add(&res.w2, &w.tau)
	res.w2.Mul(&res.w2, e)
	res.w2.Add(&res.w2, &w.s2)

	return res
}

// Verify returns true if the given message, challenge and response are valid
// for the ZKP, and false otherwise.
func Verify(h, a, b, c *secp256k1.Point, msg *Message, res *Response, e *secp256k1.Fn) bool {
	var actual, expected, hPow secp256k1.Point

	expected.BaseExp(&res.y)
	hPow.Scale(h, &res.w)
	expected.Add(&expected, &hPow)

	actual.Scale(b, e)
	actual.Add(&actual, &msg.m)

	if !actual.Eq(&expected) {
		return false
	}

	expected.BaseExp(&res.z)
	hPow.Scale(h, &res.w1)
	expected.Add(&expected, &hPow)

	actual.Scale(a, e)
	actual.Add(&actual, &msg.m1)

	if !actual.Eq(&expected) {
		return false
	}

	expected.Scale(b, &res.z)
	hPow.Scale(h, &res.w2)
	expected.Add(&expected, &hPow)

	actual.Scale(c, e)
	actual.Add(&actual, &msg.m2)

	if !actual.Eq(&expected) {
		return false
	}

	return true
}
