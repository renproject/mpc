package open_test

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/renproject/mpc/testutil"
	"github.com/renproject/secp256k1-go"

	"github.com/renproject/mpc/open"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/curve"
	stu "github.com/renproject/shamir/testutil"
)

// The main properties that we want to test for the Opener state machine are
//
//	1. The state transition logic is as described in the documentation.
//	2. Once enough valid shares have been received for construction, the
//	correct share is reconstructed.
//	3. The correct events are emmitted upon processing messages in each state.
//	4. In a network of n nodes, each holding a share of a secret, all honest
//	nodes will eventually be able to reconstruct the secret in the presence of
//	n-k malicious nodes where k is the reconstruction threshold of the secret.
var _ = Describe("Opener", func() {
	rand.Seed(int64(time.Now().Nanosecond()))

	// Pedersen commitment system parameter. For testing this can be random,
	// but in a real world use case this should be chosen appropriately.
	h := curve.Random()

	/*
		Describe("Properties", func() {
			var n, k int
			var indices []open.Fn
			var opener open.Opener
			var secret open.Fn
			var shares shamir.VerifiableShares
			var c shamir.Commitment
			var sharer shamir.VSSharer

			JustBeforeEach(func() {
				n = 20
				k = 7

				indices = stu.SequentialIndices(n)
				secret = secp256k1.RandomSecp256k1N()
				sharer = shamir.NewVSSharer(indices, h)
				shares = make(shamir.VerifiableShares, n)
				c = shamir.NewCommitmentWithCapacity(k)
				sharer.Share(&shares, &c, secret, k)

				// Randomise the order of the shares.
				rand.Shuffle(len(shares), func(i, j int) {
					shares[i], shares[j] = shares[j], shares[i]
				})

				opener = open.New(indices, h)
			})

			InStateWaitingCK0 := func(k int) bool {
				return opener.K() == k && opener.I() == 0
			}

			ProgressToWaitingI := func(i int) {
				_ = opener.TransitionReset(c, k)
				for j := 0; j < i; j++ {
					_ = opener.TransitionShare(shares[j])
				}
			}

			ProgressToDone := func() { ProgressToWaitingI(k) }

			//
			// State transition logic
			//

			Context("State transitions (1)", func() {
				Context("Uninitalised State", func() {
					It("should be in the Uninitalised state after construction", func() {
						Expect(opener.K() < 1).To(BeTrue())
					})

					Specify("Reset(c, k) -> Waiting(c, k, 0)", func() {
						_ = opener.TransitionReset(c, k)
						Expect(InStateWaitingCK0(k)).To(BeTrue())
					})

					Specify("Share -> Do nothing", func() {
						_ = opener.TransitionShare(shares[rand.Intn(n)])
						Expect(opener.K() < 1).To(BeTrue())
					})
				})

				Context("Waiting State", func() {
					Specify("Reset(c, k) -> Waiting(c, k, 0)", func() {
						for i := 0; i < k; i++ {
							ProgressToWaitingI(i)
							_ = opener.TransitionReset(c, k)
							Expect(InStateWaitingCK0(k)).To(BeTrue())
						}
					})

					Specify("(i < k-1) Share, Valid(c) -> Waiting(c, k, i+1)", func() {
						i := rand.Intn(k - 1)
						ProgressToWaitingI(i)
						_ = opener.TransitionShare(shares[i])
						Expect(opener.I()).To(Equal(i + 1))
					})

					Specify("(i = k-1) Share, Valid(c) -> Done(c)", func() {
						ProgressToWaitingI(k - 1)
						_ = opener.TransitionShare(shares[k-1])
						Expect(opener.I() >= k).To(BeTrue())
					})

					Context("Share, not Valid(c) -> Do nothing", func() {
						Specify("wrong index", func() {
							i := rand.Intn(k)
							ProgressToWaitingI(i)
							badShare := shares[i]
							stu.PerturbIndex(&badShare)
							_ = opener.TransitionShare(badShare)
							Expect(opener.I()).To(Equal(i))
						})
						Specify("wrong value", func() {
							i := rand.Intn(k)
							ProgressToWaitingI(i)
							badShare := shares[i]
							stu.PerturbValue(&badShare)
							_ = opener.TransitionShare(badShare)
							Expect(opener.I()).To(Equal(i))
						})

						Specify("wrong decommitment", func() {
							i := rand.Intn(k)
							ProgressToWaitingI(i)
							badShare := shares[i]
							stu.PerturbDecommitment(&badShare)
							_ = opener.TransitionShare(badShare)
							Expect(opener.I()).To(Equal(i))
						})
					})
				})

				Context("Done State", func() {
					Specify("Reset(c, k) -> Waiting(c, k, 0)", func() {
						for i := 0; i < k; i++ {
							ProgressToWaitingI(i)
							_ = opener.TransitionReset(c, k)
							Expect(InStateWaitingCK0(k)).To(BeTrue())
						}
					})

					Specify("Share, Valid(c) -> Do Nothing", func() {
						ProgressToDone()
						_ = opener.TransitionShare(shares[k])
						Expect(opener.I()).To(Equal(k + 1))
					})

					Context("Share, not Valid(c) -> Do nothing", func() {
						Specify("wrong index", func() {
							ProgressToDone()
							badShare := shares[k]
							stu.PerturbIndex(&badShare)
							_ = opener.TransitionShare(badShare)
							Expect(opener.I()).To(Equal(k))
						})

						Specify("wrong value", func() {
							ProgressToDone()
							badShare := shares[k]
							stu.PerturbValue(&badShare)
							_ = opener.TransitionShare(badShare)
							Expect(opener.I()).To(Equal(k))
						})

						Specify("wrong decommitment", func() {
							ProgressToDone()
							badShare := shares[k]
							stu.PerturbDecommitment(&badShare)
							_ = opener.TransitionShare(badShare)
							Expect(opener.I()).To(Equal(k))
						})
					})
				})
			})

			//
			// Reconstruction
			//

			Context("Reconstruction (2)", func() {
				It("should have the correct secret once Done", func() {
					ProgressToDone()
					reconstructed := opener.Secret()
					Expect(reconstructed.Eq(&secret)).To(BeTrue())

					for i := k; i < n; i++ {
						_ = opener.TransitionShare(shares[i])
						reconstructed = opener.Secret()
						Expect(reconstructed.Eq(&secret)).To(BeTrue())
					}
				})
			})

			//
			// Events
			//

			Context("Events (3)", func() {
				Context("Reset events", func() {
					Specify("Not yet done in a sharing instance -> Aborted", func() {
						ProgressToWaitingI(rand.Intn(k - 1))
						event := opener.TransitionReset(c, k)
						Expect(event).To(Equal(open.Aborted))
					})

					Specify("Otherwise -> Reset", func() {
						// Uninitialised
						event := opener.TransitionReset(c, k)
						Expect(event).To(Equal(open.Reset))

						// Done
						ProgressToDone()
						for i := 0; i < rand.Intn(n-k); i++ {
							_ = opener.TransitionShare(shares[i+k])
						}
						event = opener.TransitionReset(c, k)
						Expect(event).To(Equal(open.Reset))
					})
				})

				Context("Share events", func() {
					Specify("Uninitialised -> Ignored", func() {
						event := opener.TransitionShare(shares[0])
						Expect(event).To(Equal(open.Ignored))
					})

					Specify("Waiting, i < k-1 -> ShareAdded", func() {
						i := rand.Intn(k - 1)
						ProgressToWaitingI(i)
						event := opener.TransitionShare(shares[i])
						Expect(event).To(Equal(open.ShareAdded))
					})

					Specify("Done -> ShareAdded", func() {
						ProgressToDone()
						for i := k; i < n; i++ {
							event := opener.TransitionShare(shares[i])
							Expect(event).To(Equal(open.ShareAdded))
						}
					})

					Specify("Waiting, i = k-1 -> Done", func() {
						ProgressToWaitingI(k - 1)
						event := opener.TransitionShare(shares[k-1])
						Expect(event).To(Equal(open.Done))
					})

					Context("Invalid shares", func() {
						Specify("Invalid share", func() {
							ProgressToWaitingI(0)

							// Index
							badShare := shares[0]
							stu.PerturbIndex(&badShare)
							event := opener.TransitionShare(badShare)
							Expect(event).To(Equal(open.InvalidShare))

							// Value
							badShare = shares[0]
							stu.PerturbValue(&badShare)
							event = opener.TransitionShare(badShare)
							Expect(event).To(Equal(open.InvalidShare))

							// Decommitment
							badShare = shares[0]
							stu.PerturbDecommitment(&badShare)
							event = opener.TransitionShare(badShare)
							Expect(event).To(Equal(open.InvalidShare))

							for i := 0; i < n; i++ {
								_ = opener.TransitionShare(shares[i])

								// Index
								badShare = shares[i]
								stu.PerturbIndex(&badShare)
								event := opener.TransitionShare(badShare)
								Expect(event).To(Equal(open.InvalidShare))

								// Value
								badShare = shares[i]
								stu.PerturbValue(&badShare)
								event = opener.TransitionShare(badShare)
								Expect(event).To(Equal(open.InvalidShare))

								// Decommitment
								badShare = shares[i]
								stu.PerturbDecommitment(&badShare)
								event = opener.TransitionShare(badShare)
								Expect(event).To(Equal(open.InvalidShare))
							}
						})

						Specify("Duplicate share", func() {
							ProgressToWaitingI(0)
							for i := 0; i < n; i++ {
								_ = opener.TransitionShare(shares[i])

								for j := 0; j <= i; j++ {
									event := opener.TransitionShare(shares[j])
									Expect(event).To(Equal(open.IndexDuplicate))
								}
							}
						})

						Specify("Index out of range", func() {
							// To reach this case, we need a valid share that is
							// out of the normal range of indices. We thus need to
							// utilise the sharer to do this.
							indices = stu.SequentialIndices(n + 1)
							sharer = shamir.NewVSSharer(indices, h)
							shares = make(shamir.VerifiableShares, n+1)
							c = shamir.NewCommitmentWithCapacity(k)
							sharer.Share(&shares, &c, secret, k)

							// Perform the test
							ProgressToWaitingI(n)
							event := opener.TransitionShare(shares[n])
							Expect(event).To(Equal(open.IndexOutOfRange))
						})
					})
				})
			})
		})
	*/

	//
	// Network
	//

	Context("Network (4)", func() {
		fmt.Println("here")
		n := 20
		k := 7

		indices := stu.SequentialIndices(n)
		shares := make(shamir.VerifiableShares, n)
		c := shamir.NewCommitmentWithCapacity(k)
		machines := make([]Machine, n)
		sharer := shamir.NewVSSharer(indices, h)
		secret := secp256k1.RandomSecp256k1N()
		sharer.Share(&shares, &c, secret, k)
		ids := make([]ID, n)

		for i := range indices {
			id := ID(i)
			machine := newMachine(id, n, k, h, shares[i], c, open.New(indices, h))
			machines[i] = &machine
			ids[i] = id
		}

		// Pick the IDs that will be simulated as offline.
		rand.Shuffle(len(ids), func(i, j int) {
			ids[i], ids[j] = ids[j], ids[i]
		})
		isOffline := make(map[ID]bool)
		offline := rand.Intn(n - k + 1)
		offline = n - k
		fmt.Printf("offline = %v\n", offline)
		for i := 0; i < offline; i++ {
			isOffline[ids[i]] = true
		}
		for i := offline; i < n; i++ {
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
		network := NewNetwork(machines, shuffleMsgs, openMarshaler{})
		network.SetCaptureHist(true)

		It("all openers should eventaully open the correct secret", func() {
			_, err := network.Run()
			Expect(err).ToNot(HaveOccurred())

			for _, machine := range machines {
				if isOffline[machine.ID()] {
					continue
				}
				reconstructed := machine.(*openMachine).Secret()
				if !reconstructed.Eq(&secret) {
					network.Dump()
					Fail(fmt.Sprintf("machine with ID %v got the wrong secret", machine.ID()))
				}
			}
		})
	})

	FContext("Debugging", func() {
		It("the problem should get solved ;)", func() {
			debugger := NewDebugger("./dump", openMarshaler{})

			debugger.Step()
			Expect(true).To(BeTrue())
		})
	})
})

type shareMsg struct {
	share    shamir.VerifiableShare
	from, to ID
}

func (msg shareMsg) From() ID { return msg.from }
func (msg shareMsg) To() ID   { return msg.to }

func (msg *shareMsg) writeBytes(dst []byte) {
	binary.BigEndian.PutUint32(dst[:4], uint32(msg.from))
	binary.BigEndian.PutUint32(dst[4:8], uint32(msg.to))
	msg.share.GetBytes(dst[8:])
}

func (msg *shareMsg) setBytes(bs []byte) {
	msg.from = ID(binary.BigEndian.Uint32(bs[:4]))
	msg.to = ID(binary.BigEndian.Uint32(bs[4:8]))
	msg.share.SetBytes(bs[8:])
}

type openMarshaler struct{}

func (m openMarshaler) MarshalMessages(w io.Writer, messages []Message) error {
	var bs [104]byte
	binary.BigEndian.PutUint32(bs[:4], uint32(len(messages)))

	_, err := w.Write(bs[:4])
	if err != nil {
		return err
	}

	for _, msg := range messages {
		s := msg.(shareMsg)
		s.writeBytes(bs[:])
		_, err := w.Write(bs[:])
		if err != nil {
			return err
		}
	}

	return nil
}

func (m openMarshaler) UnmarshalMessages(r io.Reader) ([]Message, error) {
	var bs [104]byte
	_, err := io.ReadFull(r, bs[:4])
	if err != nil {
		return nil, err
	}
	l := binary.BigEndian.Uint32(bs[:4])

	messages := make([]Message, l)

	for i := range messages {
		_, err := io.ReadFull(r, bs[:])
		if err != nil {
			return nil, err
		}
		s := shareMsg{}
		s.setBytes(bs[:])
		messages[i] = s
	}

	return messages, nil
}

func (m openMarshaler) MarshalMachines(w io.Writer, machines []Machine) error {
	var bs [4]byte

	// n
	binary.BigEndian.PutUint32(bs[:], uint32(len(machines)))
	nWritten, err := w.Write(bs[:])
	if err != nil {
		return err
	}
	if len(machines) == 0 {
		return nil
	}
	fmt.Printf("[n] %v bytes\n", nWritten)

	// k
	k := machines[0].(*openMachine).k
	binary.BigEndian.PutUint32(bs[:], uint32(k))
	nWritten, err = w.Write(bs[:])
	if err != nil {
		return err
	}
	fmt.Printf("[k] %v bytes\n", nWritten)

	// h
	h := machines[0].(*openMachine).h
	nWritten, err = h.Marshal(w, h.SizeHint())
	if err != nil {
		return err
	}
	fmt.Printf("[h] %v bytes\n", nWritten+h.SizeHint())

	// shares
	nWritten = 0
	for i := range machines {
		share := machines[i].(*openMachine).share
		t, err := share.Marshal(w, share.SizeHint())
		nWritten += t + share.SizeHint()
		if err != nil {
			return err
		}
	}
	fmt.Printf("[shares] %v bytes\n", nWritten)

	// ids
	nWritten = 0
	for i := range machines {
		binary.BigEndian.PutUint32(bs[:], uint32(machines[i].(*openMachine).id))
		t, err := w.Write(bs[:])
		nWritten += t
		if err != nil {
			return err
		}
	}
	fmt.Printf("[ids] %v bytes\n", nWritten)

	// commitment
	com := machines[0].(*openMachine).commitment
	nWritten, err = com.Marshal(w, com.SizeHint())
	if err != nil {
		return err
	}
	fmt.Printf("[commitment] %v bytes\n", nWritten+com.SizeHint())

	return nil
}

func (m openMarshaler) UnmarshalMachines(r io.Reader) ([]Machine, error) {
	var bs [4]byte

	// n
	nRead, err := io.ReadFull(r, bs[:])
	if err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint32(bs[:]))
	fmt.Printf("[n] %v bytes\n", nRead)

	// k
	nRead, err = io.ReadFull(r, bs[:])
	if err != nil {
		return nil, err
	}
	k := int(binary.BigEndian.Uint32(bs[:]))
	fmt.Printf("[k] %v bytes\n", nRead)

	// h
	h := curve.New()
	nRead, err = h.Unmarshal(r, h.SizeHint())
	if err != nil {
		return nil, err
	}
	fmt.Printf("[h] %v bytes\n", h.SizeHint()-nRead)

	// shares
	nRead = 0
	shares := make(shamir.VerifiableShares, n)
	for i := range shares {
		t, err := shares[i].Unmarshal(r, shares[i].SizeHint())
		nRead += shares[i].SizeHint() - t
		if err != nil {
			return nil, err
		}
	}
	fmt.Printf("[shares] %v bytes\n", nRead)

	// ids
	nRead = 0
	ids := make([]ID, n)
	for i := range ids {
		t, err := io.ReadFull(r, bs[:])
		nRead += t
		if err != nil {
			return nil, err
		}
		id := binary.BigEndian.Uint32(bs[:])
		ids[i] = ID(id)
	}
	fmt.Printf("[ids] %v bytes\n", nRead)

	// commitment
	com := shamir.NewCommitmentWithCapacity(k)
	nRead, err = com.Unmarshal(r, 4+k*h.SizeHint())
	if err != nil {
		return nil, err
	}
	fmt.Printf("[commitment] %v bytes\n", 4+k*h.SizeHint()-nRead)

	// Reconstruct indices
	indices := make([]secp256k1.Secp256k1N, n)
	for i := range shares {
		share := shares[i].Share()
		indices[i] = share.Index()
	}

	machines := make([]Machine, n)
	for i := range machines {
		om := open.New(indices, h)
		m := newMachine(ids[i], n, k, h, shares[i], com, om)
		machines[i] = &m
	}

	return machines, nil
}

type openMachine struct {
	id         ID
	n, k       int
	h          curve.Point
	share      shamir.VerifiableShare
	commitment shamir.Commitment
	opener     open.Opener
}

func newMachine(
	id ID,
	n, k int,
	h curve.Point,
	share shamir.VerifiableShare,
	commitment shamir.Commitment,
	opener open.Opener,
) openMachine {
	opener.TransitionReset(commitment, k)
	_ = opener.TransitionShare(share)
	return openMachine{id, n, k, h, share, commitment, opener}
}

func (om *openMachine) Secret() open.Fn {
	return om.opener.Secret()
}

func (om *openMachine) ID() ID {
	return om.id
}

func (om *openMachine) InitialMessages() []Message {
	messages := make([]Message, om.n-1)[:0]
	for i := 0; i < om.n; i++ {
		if ID(i) == om.id {
			continue
		}
		messages = append(messages, shareMsg{
			share: om.share,
			from:  om.id,
			to:    ID(i),
		})
	}
	return messages
}

func (om *openMachine) Handle(msg Message) []Message {
	switch msg := msg.(type) {
	case shareMsg:
		om.opener.TransitionShare(msg.share)
		return nil

	default:
		panic("unexpected message")
	}
}