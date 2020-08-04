package mulzkp

import (
	"crypto/sha256"

	"github.com/renproject/mpc/mulopen/mulzkp/zkp"
	"github.com/renproject/secp256k1"
)

type Proof struct {
	msg zkp.Message
	res zkp.Response
}

func CreateProof(h, a, b, c *secp256k1.Point, alpha, beta, rho, sigma, tau secp256k1.Fn) Proof {
	msg, w := zkp.New(h, b, alpha, beta, rho, sigma, tau)
	e := computeChallenge(a, b, c, &msg)
	res := zkp.ResponseForChallenge(&w, &e)

	return Proof{msg, res}
}

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
