package testutil

import (
	"fmt"
	"os"
)

type ID int32

const NetworkID = ID(-1)

type Message interface {
	From() ID
	To() ID
}

type MessageMarshaler interface {
	MarshalMessages([]Message) ([]byte, error)
	UnmarshalMessages([]byte) ([]Message, error)
}

type Machine interface {
	ID() ID
	InitialMessages() []Message
	Handle(Message) []Message
}

type Network struct {
	msgBufCurr, msgBufNext []Message
	machines               []Machine
	processMsgs            func([]Message)
	indexOfID              map[ID]int

	captureHist bool
	msgHist     []Message
	marshaler   MessageMarshaler
}

func NewNetwork(machines []Machine, processMsgs func([]Message), marshaler MessageMarshaler) Network {
	n := len(machines)
	indexOfID := make(map[ID]int)

	for i, machine := range machines {
		if _, ok := indexOfID[machine.ID()]; ok {
			panic(fmt.Sprintf("two machines can't have the same ID: found duplicate ID %v", machine.ID()))
		}
		indexOfID[machine.ID()] = i
	}

	return Network{
		msgBufCurr: make([]Message, (n-1)*n)[:0],
		msgBufNext: make([]Message, (n-1)*n)[:0],

		// Copy the machines instead?
		machines: machines,

		processMsgs: processMsgs,
		indexOfID:   indexOfID,

		// Try to do something clever with the first allocation size?
		captureHist: false,
		msgHist:     make([]Message, n)[:0],
		marshaler:   marshaler,
	}
}

func (net *Network) SetCaptureHist(b bool) {
	net.captureHist = b
}

func (net *Network) Run() ([]Machine, error) {
	// Fill the message buffer with the first messages.
	net.msgBufCurr = net.msgBufCurr[:0]
	for _, machine := range net.machines {
		messages := machine.InitialMessages()
		if messages != nil {
			net.msgBufCurr = append(net.msgBufCurr, messages...)
		}
	}

	// Each loop is one round in the protocol.
	for {
		for _, msg := range net.msgBufCurr {
			// Add the about to be delivered message to the history.
			if net.captureHist {
				net.msgHist = append(net.msgHist, msg)
			}

			err := net.deliver(msg)
			if err != nil {
				// If we get here then the machine we just tried to deliver the
				// message to panicked.
				net.Dump()

				return nil, err
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

	return net.machines, nil
}

func (net *Network) deliver(msg Message) (err error) {
	err = nil

	if net.captureHist {
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

func (net *Network) Dump() {
	// TODO: Handle errors and save file in a more sensible place.  Consider
	// taking the file location to be a parameter somewhere.
	file, err := os.Create("./dump")
	if err != nil {
		fmt.Printf("unable to create dump file: %v", err)
	}
	defer file.Close()

	bs, err := net.marshaler.MarshalMessages(net.msgHist)
	if err != nil {
		fmt.Printf("unable to marshal message history: %v", err)
	}
	_, err = file.Write(bs)
	if err != nil {
		fmt.Printf("unable to write to file: %v", err)
	}
}
