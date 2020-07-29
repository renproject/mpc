package rkpg

func (rkpger RKPGer) SizeHint() int {
	return rkpger.state.SizeHint()
}

func (rkpger RKPGer) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := rkpger.state.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return buf, rem, err
}

func (rkpger *RKPGer) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := rkpger.state.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return buf, rem, err
}
