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

	hPow.ScaleUnsafe(h, &w.s)
	msg.m.BaseExpUnsafe(&w.d)
	msg.m.AddUnsafe(&msg.m, &hPow)

	hPow.ScaleUnsafe(h, &w.s1)
	msg.m1.BaseExpUnsafe(&w.x)
	msg.m1.AddUnsafe(&msg.m1, &hPow)

	hPow.ScaleUnsafe(h, &w.s2)
	msg.m2.ScaleUnsafe(b, &w.x)
	msg.m2.AddUnsafe(&msg.m2, &hPow)

	return msg, w
}

func ResponseForChallenge(w *Witness, e *secp256k1.Fn) Response {
	var res Response

	res.y.MulUnsafe(e, &w.beta)
	res.y.AddUnsafe(&res.y, &w.d)

	res.w.MulUnsafe(e, &w.sigma)
	res.w.AddUnsafe(&res.w, &w.s)

	res.z.MulUnsafe(e, &w.alpha)
	res.z.AddUnsafe(&res.z, &w.x)

	res.w1.MulUnsafe(e, &w.rho)
	res.w1.AddUnsafe(&res.w1, &w.s1)

	res.w2.MulUnsafe(&w.sigma, &w.alpha)
	res.w2.Negate(&res.w2)
	res.w2.AddUnsafe(&res.w2, &w.tau)
	res.w2.MulUnsafe(&res.w2, e)
	res.w2.AddUnsafe(&res.w2, &w.s2)

	return res
}

func Verify(h, a, b, c *secp256k1.Point, msg *Message, res *Response, e *secp256k1.Fn) bool {
	var actual, expected, hPow secp256k1.Point

	expected.BaseExpUnsafe(&res.y)
	hPow.ScaleUnsafe(h, &res.w)
	expected.AddUnsafe(&expected, &hPow)

	actual.ScaleUnsafe(b, e)
	actual.AddUnsafe(&actual, &msg.m)

	if !actual.Eq(&expected) {
		return false
	}

	expected.BaseExpUnsafe(&res.z)
	hPow.ScaleUnsafe(h, &res.w1)
	expected.AddUnsafe(&expected, &hPow)

	actual.ScaleUnsafe(a, e)
	actual.AddUnsafe(&actual, &msg.m1)

	if !actual.Eq(&expected) {
		return false
	}

	expected.ScaleUnsafe(b, &res.z)
	hPow.ScaleUnsafe(h, &res.w2)
	expected.AddUnsafe(&expected, &hPow)

	actual.ScaleUnsafe(c, e)
	actual.AddUnsafe(&actual, &msg.m2)

	if !actual.Eq(&expected) {
		return false
	}

	return true
}
