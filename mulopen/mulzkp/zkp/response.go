package zkp

import "github.com/renproject/secp256k1"

// The Response for a challenge in the ZKP.
type Response struct {
	y, w, z, w1, w2 secp256k1.Fn
}

// SizeHint implements the surge.SizeHinter interface.
func (res Response) SizeHint() int {
	return res.y.SizeHint() +
		res.w.SizeHint() +
		res.z.SizeHint() +
		res.w1.SizeHint() +
		res.w2.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (res Response) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := res.y.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = res.w.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = res.z.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = res.w1.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return res.w2.Marshal(buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (res *Response) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := res.y.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = res.w.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = res.z.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = res.w1.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return res.w2.Unmarshal(buf, rem)
}
