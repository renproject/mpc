package mulzkp

import "github.com/renproject/mpc/mulopen/mulzkp/zkp"

// A Proof for the ZKP.
type Proof struct {
	msg zkp.Message
	res zkp.Response
}

// SizeHint implements the surge.SizeHinter interface.
func (p Proof) SizeHint() int { return p.msg.SizeHint() + p.res.SizeHint() }

// Marshal implements the surge.Marshaler interface.
func (p Proof) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := p.msg.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return p.res.Marshal(buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (p *Proof) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := p.msg.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return p.res.Unmarshal(buf, rem)
}
