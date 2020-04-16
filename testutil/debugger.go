package testutil

import (
	"io/ioutil"
)

type Debugger struct {
	messages []Message
	machines []Machine
}

func NewDebugger(file string, machines []Machine, marshaler MessageMarshaler) Debugger {
	bs, err := ioutil.ReadFile(file)
	if err != nil {
		panic(err)
	}
	messages, err := marshaler.UnmarshalMessages(bs)
	if err != nil {
		panic(err)
	}

	return Debugger{messages, machines}
}

func (dbg *Debugger) Step() {
	msg := dbg.messages[0]
	_ = dbg.machines[msg.To()].Handle(msg)
}
