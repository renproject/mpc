package zkp

import "github.com/renproject/secp256k1"

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
