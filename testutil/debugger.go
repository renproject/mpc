package testutil

import (
	"os"
)

type Debugger struct {
	messages []Message
	machines []Machine
}

func NewDebugger(filename string, marshaler RunMarshaler) Debugger {
	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}

	machines, err := marshaler.UnmarshalMachines(file)
	if err != nil {
		panic(err)
	}

	messages, err := marshaler.UnmarshalMessages(file)
	if err != nil {
		panic(err)
	}

	return Debugger{messages, machines}
}

func (dbg *Debugger) Step() {
	msg := dbg.messages[0]
	_ = dbg.machines[msg.To()].Handle(msg)
}
