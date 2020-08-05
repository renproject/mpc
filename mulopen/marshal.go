package mulopen

import "github.com/renproject/surge"

// SizeHint implements the surge.SizeHinter interface.
func (mulopener MulOpener) SizeHint() int {
	return surge.SizeHint(mulopener.shareBufs) +
		surge.SizeHint(mulopener.batchSize) +
		surge.SizeHint(mulopener.k) +
		surge.SizeHint(mulopener.aCommitmentBatch) +
		surge.SizeHint(mulopener.bCommitmentBatch) +
		surge.SizeHint(mulopener.rzgCommitmentBatch) +
		surge.SizeHint(mulopener.indices) +
		mulopener.h.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (mulopener MulOpener) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := surge.Marshal(mulopener.shareBufs, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.MarshalU32(mulopener.batchSize, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.MarshalU32(mulopener.k, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(mulopener.aCommitmentBatch, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(mulopener.bCommitmentBatch, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(mulopener.rzgCommitmentBatch, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(mulopener.indices, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return mulopener.h.Marshal(buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (mulopener *MulOpener) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := surge.Unmarshal(&mulopener.shareBufs, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.UnmarshalU32(&mulopener.batchSize, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.UnmarshalU32(&mulopener.k, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&mulopener.aCommitmentBatch, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&mulopener.bCommitmentBatch, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&mulopener.rzgCommitmentBatch, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&mulopener.indices, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return mulopener.h.Unmarshal(buf, rem)
}

// SizeHint implements the surge.SizeHinter interface.
func (msg Message) SizeHint() int {
	return msg.VShare.SizeHint() +
		msg.Commitment.SizeHint() +
		msg.Proof.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (msg Message) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := msg.VShare.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = msg.Commitment.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return msg.Proof.Marshal(buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (msg *Message) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := msg.VShare.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = msg.Commitment.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return msg.Proof.Unmarshal(buf, rem)
}
