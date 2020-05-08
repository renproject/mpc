package testutil

import (
	"os"
	"reflect"

	"github.com/renproject/surge"
)

// A Debugger provides functionality for loading debug states, and performing
// debugging operations on the given debug state (which consists of a message
// history and initial states for the machines).
type Debugger struct {
	messages []Message
	machines []Machine

	pos int
}

// NewDebugger creates a new Debugger from the file with the given filename.
// The messageType and machineType arguments are used to know how to correctly
// unmarshal the file.
func NewDebugger(filename string, messageType, machineType interface{}) Debugger {
	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}

	/*
		if _, ok := v.(Machine); !ok {
			panic("given type does not implement the Machine interface")
		}
	*/

	// Unmarshal machines.
	sl := reflect.New(reflect.SliceOf(reflect.TypeOf(machineType)))
	_, err = surge.Unmarshal(file, sl.Interface(), surge.MaxBytes)
	if err != nil {
		panic(err)
	}

	var machines []Machine
	for i := 0; i < reflect.Indirect(sl).Len(); i++ {
		machines = append(machines, reflect.Indirect(sl).Index(i).Addr().Interface().(Machine))
	}

	// Unmarshal messages.
	sl = reflect.New(reflect.SliceOf(reflect.TypeOf(messageType)))
	_, err = surge.Unmarshal(file, sl.Interface(), surge.MaxBytes)
	if err != nil {
		panic(err)
	}

	var messages []Message
	for i := 0; i < reflect.Indirect(sl).Len(); i++ {
		messages = append(messages, reflect.Indirect(sl).Index(i).Addr().Interface().(Message))
	}

	pos := 0

	return Debugger{messages, machines, pos}
}

// Step processes the next message in the message history. It returns true if
// there are more messages in the hostory, and false otherwise
func (dbg *Debugger) Step() bool {
	if dbg.pos == len(dbg.messages) {
		return false
	}
	msg := dbg.messages[dbg.pos]
	_ = dbg.machines[msg.To()].Handle(msg)
	dbg.pos++

	return true
}

// MachineByID returns the machine for the given ID in its current state.
func (dbg *Debugger) MachineByID(id ID) Machine {
	for _, machine := range dbg.machines {
		if machine.ID() == id {
			return machine
		}
	}

	return nil
}

// MessagesForID returns all of the messages in the message history that are
// addressed to the given ID.
func (dbg *Debugger) MessagesForID(id ID) []Message {
	msgsForID := make([]Message, 0)

	for _, m := range dbg.messages {
		if m.To() == id {
			msgsForID = append(msgsForID, m)
		}
	}

	return msgsForID
}
