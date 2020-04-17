package open_test

import (
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
var _ = Describe("Opener", func() {
	rand.Seed(int64(time.Now().Nanosecond()))

	// Pedersen commitment system parameter. For testing this can be random,
	// but in a real world use case this should be chosen appropriately.
	h := curve.Random()

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
			k = 6

			indices = stu.SequentialIndices(n)
			opener = open.New(indices, h)
			secret = secp256k1.RandomSecp256k1N()
			sharer = shamir.NewVSSharer(indices, h)
			shares = make(shamir.VerifiableShares, n)
			c = shamir.NewCommitmentWithCapacity(k)
			sharer.Share(&shares, &c, secret, k)

			// Randomise the order of the shares.
			rand.Shuffle(len(shares), func(i, j int) {
				shares[i], shares[j] = shares[j], shares[i]
			})
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

						// Randomise the order of the shares.
						rand.Shuffle(len(shares), func(i, j int) {
							shares[i], shares[j] = shares[j], shares[i]
						})

						// Perform the test
						ProgressToWaitingI(n)
						event := opener.TransitionShare(shares[n])
						Expect(event).To(Equal(open.IndexOutOfRange))
					})
				})
			})
		})
	})

	Context("Network", func() {
		n := 10
		k := 4

		indices := stu.SequentialIndices(n)
		shares := make(shamir.VerifiableShares, n)
		c := shamir.NewCommitmentWithCapacity(k)
		machines := make([]Machine, n)
		sharer := shamir.NewVSSharer(indices, h)
		secret := secp256k1.RandomSecp256k1N()

		sharer.Share(&shares, &c, secret, k)

		for i := range indices {
			machine := newMachine(ID(i), n, k, shares[i], c, open.New(indices, h))
			machines[i] = &machine
		}

		network := NewNetwork(machines, func([]Message) {}, openMarshaler{})

		Specify("all openers should eventaully open the correct secret", func() {
			_, err := network.Run()
			Expect(err).ToNot(HaveOccurred())

			for _, machine := range machines {
				reconstructed := machine.(*openMachine).Secret()
				Expect(reconstructed.Eq(&secret)).To(BeTrue())
			}
		})
	})

	/*
		FContext("Debugging", func() {
			n := 10

			indices := stu.SequentialIndices(n)
			machines := make([]Machine, n)

			for i, ind := range indices {
				machine := newMachine(ID(ind.Uint64()), n, shamir.VerifiableShare{}, open.New(indices, h))
				machines[i] = &machine
			}

			debugger := NewDebugger("./dump", machines, openMarshaler{})

			debugger.Step()
		})
	*/
})

type shareMsg struct {
	share    shamir.VerifiableShare
	from, to ID
}

func (msg shareMsg) From() ID { return msg.from }
func (msg shareMsg) To() ID   { return msg.to }

func (msg *shareMsg) writeBytes(dst []byte) {
	// from
	dst[0] = byte(msg.from)
	dst[1] = byte(msg.from >> 8)
	dst[2] = byte(msg.from >> 16)
	dst[3] = byte(msg.from >> 24)

	// to
	dst[4] = byte(msg.to)
	dst[5] = byte(msg.to >> 8)
	dst[6] = byte(msg.to >> 16)
	dst[7] = byte(msg.to >> 24)

	share := msg.share.Share()
	index := share.Index()
	value := share.Value()
	r := msg.share.Decommitment()

	// share
	index.GetB32(dst[8:40])
	value.GetB32(dst[40:72])
	r.GetB32(dst[72:104])
}

func (msg *shareMsg) setBytes(bs []byte) {
	msg.from = ID(bs[0] + bs[1]<<8 + bs[2]<<16 + bs[3]<<24)
	msg.to = ID(bs[4] + bs[5]<<8 + bs[6]<<16 + bs[7]<<24)

	index, value, decom := open.Fn{}, open.Fn{}, open.Fn{}
	index.SetB32(bs[8:40])
	value.SetB32(bs[40:72])
	decom.SetB32(bs[72:104])

	share := shamir.NewShare(index, value)
	msg.share = shamir.NewVerifiableShare(share, decom)
}

type openMarshaler struct{}

func (m openMarshaler) MarshalMessages(messages []Message) ([]byte, error) {
	bs := make([]byte, 104*len(messages))

	for i, msg := range messages {
		s := msg.(shareMsg)
		s.writeBytes(bs[i*104 : (i+1)*104])
	}

	return bs, nil
}

func (m openMarshaler) UnmarshalMessages(bs []byte) ([]Message, error) {
	messages := make([]Message, len(bs)/104)

	for i := range messages {
		s := shareMsg{}
		s.setBytes(bs[i*104 : (i+1)*104])
		messages[i] = s
	}

	return messages, nil
}

type openMachine struct {
	id         ID
	n, k       int
	share      shamir.VerifiableShare
	commitment shamir.Commitment
	opener     open.Opener
}

func newMachine(
	id ID,
	n, k int,
	share shamir.VerifiableShare,
	commitment shamir.Commitment,
	opener open.Opener,
) openMachine {
	return openMachine{id, n, k, share, commitment, opener}
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
	om.opener.TransitionReset(om.commitment, om.k)
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

	return nil
}
