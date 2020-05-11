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
			_ = opener.TransitionReset(c)
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
					_ = opener.TransitionReset(c)
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
						_ = opener.TransitionReset(c)
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
						_ = opener.TransitionReset(c)
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
					event := opener.TransitionReset(c)
					Expect(event).To(Equal(open.Aborted))
				})

				Specify("Otherwise -> Reset", func() {
					// Uninitialised
					event := opener.TransitionReset(c)
					Expect(event).To(Equal(open.Reset))

					// Done
					ProgressToDone()
					for i := 0; i < rand.Intn(n-k); i++ {
						_ = opener.TransitionShare(shares[i+k])
					}
					event = opener.TransitionReset(c)
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

	//
	// Network
	//

	Context("Network (4)", func() {
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
			machine := newMachine(id, n, shares[i], c, open.New(indices, h))
			machines[i] = &machine
			ids[i] = id
		}

		// Pick the IDs that will be simulated as offline.
		offline := rand.Intn(n - k + 1)
		offline = n - k
		shuffleMsgs, isOffline := MessageShufflerDropper(ids, offline)
		network := NewNetwork(machines, shuffleMsgs)
		network.SetCaptureHist(true)

		It("all openers should eventaully open the correct secret", func() {
			err := network.Run()
			Expect(err).ToNot(HaveOccurred())

			for _, machine := range machines {
				if isOffline[machine.ID()] {
					continue
				}
				reconstructed := machine.(*openMachine).Secret()
				// Expect(reconstructed.Eq(&secret)).To(BeTrue())

				if !reconstructed.Eq(&secret) {
					network.Dump("test.dump")
					Fail(fmt.Sprintf("machine with ID %v got the wrong secret", machine.ID()))
				}
			}
		})
	})
})

type shareMsg struct {
	share    shamir.VerifiableShare
	from, to ID
}

func (msg shareMsg) From() ID { return msg.from }
func (msg shareMsg) To() ID   { return msg.to }

func (msg *shareMsg) SizeHint() int {
	return msg.share.SizeHint() + msg.from.SizeHint() + msg.to.SizeHint()
}

func (msg *shareMsg) Marshal(w io.Writer, m int) (int, error) {
	m, err := msg.share.Marshal(w, m)
	if err != nil {
		return m, err
	}
	m, err = msg.from.Marshal(w, m)
	if err != nil {
		return m, err
	}
	m, err = msg.to.Marshal(w, m)
	return m, err
}

func (msg *shareMsg) Unmarshal(r io.Reader, m int) (int, error) {
	m, err := msg.share.Unmarshal(r, m)
	if err != nil {
		return m, err
	}
	m, err = msg.from.Unmarshal(r, m)
	if err != nil {
		return m, err
	}
	m, err = msg.to.Unmarshal(r, m)
	return m, err
}

type openMachine struct {
	id         ID
	n          int
	share      shamir.VerifiableShare
	commitment shamir.Commitment
	opener     open.Opener

	lastE open.ShareEvent
}

func (om *openMachine) SizeHint() int {
	return om.id.SizeHint() +
		4 +
		om.share.SizeHint() +
		om.commitment.SizeHint() +
		om.opener.SizeHint()
}

func (om *openMachine) Marshal(w io.Writer, m int) (int, error) {
	m, err := om.id.Marshal(w, m)
	if err != nil {
		return m, err
	}

	var bs [4]byte
	binary.BigEndian.PutUint32(bs[:], uint32(om.n))
	n, err := w.Write(bs[:])
	m -= n
	if err != nil {
		return m, err
	}

	m, err = om.share.Marshal(w, m)
	if err != nil {
		return m, err
	}
	m, err = om.commitment.Marshal(w, m)
	if err != nil {
		return m, err
	}
	m, err = om.opener.Marshal(w, m)
	return m, err
}

func (om *openMachine) Unmarshal(r io.Reader, m int) (int, error) {
	m, err := om.id.Unmarshal(r, m)
	if err != nil {
		return m, err
	}

	var bs [4]byte
	n, err := io.ReadFull(r, bs[:])
	m -= n
	if err != nil {
		return m, err
	}
	v := binary.BigEndian.Uint32(bs[:])
	om.n = int(v)

	m, err = om.share.Unmarshal(r, m)
	if err != nil {
		return m, err
	}
	m, err = om.commitment.Unmarshal(r, m)
	if err != nil {
		return m, err
	}
	m, err = om.opener.Unmarshal(r, m)
	return m, err
}

func newMachine(
	id ID,
	n int,
	share shamir.VerifiableShare,
	commitment shamir.Commitment,
	opener open.Opener,
) openMachine {
	opener.TransitionReset(commitment)
	_ = opener.TransitionShare(share)
	lastE := open.ShareEvent(0)
	return openMachine{id, n, share, commitment, opener, lastE}
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
		messages = append(messages, &shareMsg{
			share: om.share,
			from:  om.id,
			to:    ID(i),
		})
	}
	return messages
}

func (om *openMachine) Handle(msg Message) []Message {
	switch msg := msg.(type) {
	case *shareMsg:
		om.lastE = om.opener.TransitionShare(msg.share)
		return nil

	default:
		panic("unexpected message")
	}
}
