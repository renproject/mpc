package testutil

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"os"

	"github.com/renproject/surge"
)

// ID represents a unique identifier for a Machine.
type ID int32

// SizeHint implements the surge.SizeHinter interface.
func (id *ID) SizeHint() int { return 4 }

// Marshal implements the surge.Marshaler interface.
func (id *ID) Marshal(w io.Writer, m int) (int, error) {
	if m < 4 {
		return m, surge.ErrMaxBytesExceeded
	}
	var bs [4]byte
	binary.BigEndian.PutUint32(bs[:], uint32(*id))
	n, err := w.Write(bs[:])
	m -= n
	return m, err
}

// Unmarshal implements the surge.Unmarshaler interface.
func (id *ID) Unmarshal(r io.Reader, m int) (int, error) {
	if m < 4 {
		return m, surge.ErrMaxBytesExceeded
	}
	var bs [4]byte
	n, err := io.ReadFull(r, bs[:])
	m -= n
	if err != nil {
		return m, err
	}
	v := binary.BigEndian.Uint32(bs[:])
	*id = ID(v)
	return m, nil
}

// The Message interface represents a message that can be sent during a network
// run. Messages must be able to give the IDs for the sender and receiver of
// the message.
type Message interface {
	From() ID
	To() ID
}

// A RunMarshaler captures the functionality of being able to marshal and
// unmarshal a message history, and also a list of machines.
type RunMarshaler interface {
	MarshalMessages(io.Writer, []Message) error
	UnmarshalMessages(io.Reader) ([]Message, error)
	MarshalMachines(io.Writer, []Machine) error
	UnmarshalMachines(io.Reader) ([]Machine, error)
}

// The Machine interface represents one of the players in a distributed
// network. Every machine must have a unique ID, and be able to handle incoming
// messages.
type Machine interface {
	ID() ID

	// InitialMessages should return the messages that a Machine sends at the
	// start of a network run, i.e. those messages that it would send before
	// having received any, if there are such messages.
	InitialMessages() []Message

	// Handle processes an incoming message and returns response messages, if
	// any.
	Handle(Message) []Message
}

// A Network is used to simulate a network of distributed Machines that send
// and recieve messages from eachother.
type Network struct {
	msgBufCurr, msgBufNext []Message
	machines               []Machine
	processMsgs            func([]Message)
	indexOfID              map[ID]int

	captureHist   bool
	msgHist       []Message
	initialStates bytes.Buffer
	marshaler     RunMarshaler
}

// NewNetwork creates a new Network object from the given machines and message
// processing function. This message processing function will be applied to all
// of the messages to be sent in a given round, before sending them. For
// example, this can be used to shuffle or drop messages from certain players
// to simulate various network conditions.
func NewNetwork(machines []Machine, processMsgs func([]Message), marshaler RunMarshaler) Network {
	n := len(machines)
	indexOfID := make(map[ID]int)

	for i, machine := range machines {
		if _, ok := indexOfID[machine.ID()]; ok {
			panic(fmt.Sprintf("two machines can't have the same ID: found duplicate ID %v", machine.ID()))
		}
		indexOfID[machine.ID()] = i
	}

	// Save initial machine state.
	var buf bytes.Buffer
	err := marshaler.MarshalMachines(&buf, machines)
	if err != nil {
		panic(err)
	}

	return Network{
		msgBufCurr: make([]Message, (n-1)*n)[:0],
		msgBufNext: make([]Message, (n-1)*n)[:0],

		// TODO: Copy the machines instead?
		machines: machines,

		processMsgs: processMsgs,
		indexOfID:   indexOfID,

		// TODO: Try to do something clever with the first allocation size?
		captureHist:   false,
		msgHist:       make([]Message, n)[:0],
		initialStates: buf,
		marshaler:     marshaler,
	}
}

// SetCaptureHist sets wether the network will capture the message history and
// create a debug file on a panic. The message history needs to be captured if
// such a debug file is to be used in a later debugging session.
func (net *Network) SetCaptureHist(b bool) {
	net.captureHist = b
}

// Run drives an execution of the network of machines to completion. The run
// will continue until there are no more messages to deliver. An error is
// returned indicating the success of the run; if message history is being
// captured, an error will be returned if any of the machines panic when
// handling a message. In all other cases, a nil error is returned.
func (net *Network) Run() error {
	// Fill the message buffer with the first messages.
	net.msgBufCurr = net.msgBufCurr[:0]
	for _, machine := range net.machines {
		messages := machine.InitialMessages()
		if messages != nil {
			net.msgBufCurr = append(net.msgBufCurr, messages...)
		}
	}
	net.processMsgs(net.msgBufCurr)

	// Each loop is one round in the protocol.
	for {
		for _, msg := range net.msgBufCurr {
			// Ignore nil messages.
			if msg == nil {
				continue
			}

			// Add the about to be delivered message to the history.
			if net.captureHist {
				net.msgHist = append(net.msgHist, msg)
			}

			err := net.deliver(msg)
			if err != nil && net.captureHist {
				// If we get here then the machine we just tried to deliver the
				// message to panicked.
				net.Dump("panic.dump")

				return err
			}
		}

		if len(net.msgBufNext) == 0 {
			// All machines have finished sending messages.
			break
		}

		// switch message buffers
		net.msgBufCurr, net.msgBufNext = net.msgBufNext, net.msgBufCurr[:0]

		// Do any processing on the messages for the next round here, e.g.
		// shuffling.
		net.processMsgs(net.msgBufCurr)
	}

	return nil
}

func (net *Network) deliver(msg Message) (err error) {
	err = nil

	if net.captureHist {
		// Catch any panics and create debug file if they occur.
		defer func() {
			r := recover()
			if r != nil {
				if e, ok := r.(error); ok {
					err = e
				} else {
					err = fmt.Errorf("panic: %v", r)
				}
			}
		}()
	}

	res := net.machines[net.indexOfID[msg.To()]].Handle(msg)
	if res != nil {
		net.msgBufNext = append(net.msgBufNext, res...)
	}

	return
}

// Dump saves the initial state of the machines and the message history to the
// file with the given name. This file can be loaded by a Debugger to start a
// debugging session.
func (net *Network) Dump(filename string) {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("unable to create dump file: %v", err)
	}
	defer file.Close()

	fmt.Printf("dumping debug state to file %s\n", filename)

	// Write machine initial states.
	_, err = file.Write(net.initialStates.Bytes())
	if err != nil {
		fmt.Printf("unable to write initial states to file: %v", err)
	}

	err = net.marshaler.MarshalMessages(file, net.msgHist)
	if err != nil {
		fmt.Printf("unable to write message history to file: %v", err)
	}
}

// MessageShufflerDropper returns a function that can be used as the message
// processing parameter for a Network object. This message processor will
// simulate there being `offline` number of machines offline, chosen randomly;
// messages to or from these machines will be dropped. The message order will
// also be shuffled each round.
func MessageShufflerDropper(ids []ID, offline int) (func([]Message), map[ID]bool) {
	rand.Shuffle(len(ids), func(i, j int) {
		ids[i], ids[j] = ids[j], ids[i]
	})
	isOffline := make(map[ID]bool)
	for i := 0; i < offline; i++ {
		isOffline[ids[i]] = true
	}
	for i := offline; i < len(ids); i++ {
		isOffline[ids[i]] = false
	}

	shuffleMsgs := func(msgs []Message) {
		rand.Shuffle(len(msgs), func(i, j int) {
			msgs[i], msgs[j] = msgs[j], msgs[i]
		})

		// Delete any messages from the offline machines or to the offline
		// machines.
		for i, msg := range msgs {
			if isOffline[msg.From()] || isOffline[msg.To()] {
				msgs[i] = nil
			}
		}
	}

	return shuffleMsgs, isOffline
}
