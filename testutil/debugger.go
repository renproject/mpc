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

	pos     int
	machbps []machineBreakPoint
	msgbps  []messageBreakPoint
}

// NewDebugger creates a new Debugger from the file with the given filename.
// The messageType and machineType arguments are used to know how to correctly
// unmarshal the file.
func NewDebugger(filename string, messageType, machineType interface{}) Debugger {
	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}


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
	var machbps []machineBreakPoint
	var msgbps []messageBreakPoint

	return Debugger{messages, machines, pos, machbps, msgbps}
}

// Step processes the next message in the message history. It returns true if
// there are more messages in the hostory, and false otherwise
func (dbg *Debugger) Step() bool {
	msg := dbg.messages[dbg.pos]
	_ = dbg.machines[msg.To()].Handle(msg)
	dbg.pos++

	if dbg.pos == len(dbg.messages) {
		return false
	}
	return true
}

// MachineByID returns the machine for the given ID in its current state.
func (dbg Debugger) MachineByID(id ID) Machine {
	for _, machine := range dbg.machines {
		if machine.ID() == id {
			return machine
		}
	}

	return nil
}

// MessagesForID returns all of the messages in the message history that are
// addressed to the given ID.
func (dbg Debugger) MessagesForID(id ID) []Message {
	msgsForID := make([]Message, 0)

	for _, m := range dbg.messages {
		if m.To() == id {
			msgsForID = append(msgsForID, m)
		}
	}

	return msgsForID
}

// SetMachineBreakPoint registers and enables a breakpoint for the machine with
// the given ID. The breakpoint will trigger the first time that the machine is
// in a state such that the predicate returns true.
func (dbg *Debugger) SetMachineBreakPoint(id ID, pred func(Machine) bool) {
	enabled := true
	bp := machineBreakPoint{id, enabled, pred}
	dbg.machbps = append(dbg.machbps, bp)
}

// SetMessageBreakPoint registers and enables a breakpoint that will trigger
// when the next message to be handled (by any machine) satisfies the given
// predicate.
func (dbg *Debugger) SetMessageBreakPoint(pred func(Message) bool) {
	enabled := true
	bp := messageBreakPoint{enabled, pred}
	dbg.msgbps = append(dbg.msgbps, bp)
}

// Continue handles messages either until a breakpoint is triggered or there
// are no more messages to handle.
func (dbg *Debugger) Continue() {
	for {
		if dbg.machBpTriggered() || dbg.msgBpTriggered(dbg.messages[dbg.pos]) {
			break
		}

		if !dbg.Step() {
			break
		}
	}
}

func (dbg *Debugger) machBpTriggered() bool {
	for i := range dbg.machbps {
		if !dbg.machbps[i].enabled {
			continue
		}
		if dbg.machbps[i].pred(dbg.MachineByID(dbg.machbps[i].id)) {
			dbg.machbps[i].enabled = false
			return true
		}
	}
	return false
}

func (dbg *Debugger) msgBpTriggered(msg Message) bool {
	for i := range dbg.msgbps {
		if !dbg.msgbps[i].enabled {
			continue
		}
		if dbg.msgbps[i].pred(msg) {
			dbg.msgbps[i].enabled = false
			return true
		}
	}
	return false
}

type machineBreakPoint struct {
	id      ID
	enabled bool
	pred    func(Machine) bool
}

type messageBreakPoint struct {
	enabled bool
	pred    func(Message) bool
}
