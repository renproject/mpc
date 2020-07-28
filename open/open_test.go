package open_test

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/renproject/mpc/open"
	"github.com/renproject/mpc/open/openutil"
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/shamirutil"
	"github.com/renproject/surge"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/mpc/mpcutil"
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
	h := secp256k1.RandomPoint()

	Describe("Properties", func() {
		b := 5
		n := 20
		k := 7

		var (
			indices      []secp256k1.Fn
			opener       open.Opener
			secrets      []secp256k1.Fn
			setsOfShares []shamir.VerifiableShares
			commitments  []shamir.Commitment
		)

		Setup := func() (
			[]secp256k1.Fn,
			open.Opener,
			[]secp256k1.Fn,
			[]shamir.VerifiableShares,
			[]shamir.Commitment,
		) {
			indices := shamirutil.SequentialIndices(n)
			secrets := make([]secp256k1.Fn, b)
			for i := 0; i < b; i++ {
				secrets[i] = secp256k1.RandomFn()
			}

			setsOfShares := make([]shamir.VerifiableShares, b)
			for i := 0; i < b; i++ {
				setsOfShares[i] = make(shamir.VerifiableShares, n)
			}

			commitments := make([]shamir.Commitment, b)
			for i := 0; i < b; i++ {
				commitments[i] = shamir.NewCommitmentWithCapacity(k)
				shamir.VShareSecret(&setsOfShares[i], &commitments[i], indices, h, secrets[i], k)
			}

			opener = open.New(uint32(b), indices, h)

			return indices, opener, secrets, setsOfShares, commitments
		}

		JustBeforeEach(func() {
			indices, opener, secrets, setsOfShares, commitments = Setup()
		})

		InStateWaitingCK0 := func(k int) bool {
			return opener.K() == k && opener.I() == 0
		}

		ProgressToWaitingI := func(i int) {
			_ = opener.TransitionReset(commitments)
			for j := 0; j < i; j++ {
				shares := openutil.GetSharesAt(setsOfShares, j)
				_ = opener.TransitionShares(shares)
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
					_ = opener.TransitionReset(commitments)
					Expect(InStateWaitingCK0(k)).To(BeTrue())
				})

				Specify("Share -> Do nothing", func() {
					shares := openutil.GetSharesAt(setsOfShares, rand.Intn(b))
					_ = opener.TransitionShares(shares)
					Expect(opener.K() < 1).To(BeTrue())
				})
			})

			Context("Waiting State", func() {
				Specify("Reset(c, k) -> Waiting(c, k, 0)", func() {
					for i := 0; i < k; i++ {
						ProgressToWaitingI(i)
						_ = opener.TransitionReset(commitments)
						Expect(InStateWaitingCK0(k)).To(BeTrue())
					}
				})

				Specify("(i < k-1) Share, Valid(c) -> Waiting(c, k, i+1)", func() {
					i := rand.Intn(k - 1)
					ProgressToWaitingI(i)
					shares := openutil.GetSharesAt(setsOfShares, i)
					_ = opener.TransitionShares(shares)
					Expect(opener.I()).To(Equal(i + 1))
				})

				Specify("(i = k-1) Share, Valid(c) -> Done(c)", func() {
					ProgressToWaitingI(k - 1)
					shares := openutil.GetSharesAt(setsOfShares, k-1)
					_ = opener.TransitionShares(shares)
					Expect(opener.I() >= k).To(BeTrue())
				})

				Context("Share, not Valid(c) -> Do nothing", func() {
					Specify("wrong index", func() {
						// progress till i
						i := rand.Intn(k)
						ProgressToWaitingI(i)

						// perturb a random share from `sharesAtI`
						shares := openutil.GetSharesAt(setsOfShares, i)
						j := rand.Intn(b)
						shamirutil.PerturbIndex(&shares[j])
						_ = opener.TransitionShares(shares)
						Expect(opener.I()).To(Equal(i))
					})
					Specify("wrong value", func() {
						i := rand.Intn(k)
						ProgressToWaitingI(i)

						shares := openutil.GetSharesAt(setsOfShares, i)
						j := rand.Intn(b)
						shamirutil.PerturbValue(&shares[j])
						_ = opener.TransitionShares(shares)
						Expect(opener.I()).To(Equal(i))
					})

					Specify("wrong decommitment", func() {
						i := rand.Intn(k)
						ProgressToWaitingI(i)

						shares := openutil.GetSharesAt(setsOfShares, i)
						j := rand.Intn(b)
						shamirutil.PerturbDecommitment(&shares[j])
						_ = opener.TransitionShares(shares)
						Expect(opener.I()).To(Equal(i))
					})
				})
			})

			Context("Done State", func() {
				Specify("Reset(c, k) -> Waiting(c, k, 0)", func() {
					for i := 0; i < k; i++ {
						ProgressToWaitingI(i)
						_ = opener.TransitionReset(commitments)
						Expect(InStateWaitingCK0(k)).To(BeTrue())
					}
				})

				Specify("Share, Valid(c) -> Do Nothing", func() {
					ProgressToDone()
					shares := openutil.GetSharesAt(setsOfShares, k)
					_ = opener.TransitionShares(shares)
					Expect(opener.I()).To(Equal(k + 1))
				})

				Context("Share, not Valid(c) -> Do nothing", func() {
					Specify("wrong index", func() {
						ProgressToDone()
						shares := openutil.GetSharesAt(setsOfShares, k)
						j := rand.Intn(b)
						shamirutil.PerturbIndex(&shares[j])
						_ = opener.TransitionShares(shares)
						Expect(opener.I()).To(Equal(k))
					})

					Specify("wrong value", func() {
						ProgressToDone()
						shares := openutil.GetSharesAt(setsOfShares, k)
						j := rand.Intn(b)
						shamirutil.PerturbValue(&shares[j])
						_ = opener.TransitionShares(shares)
						Expect(opener.I()).To(Equal(k))
					})

					Specify("wrong decommitment", func() {
						ProgressToDone()
						shares := openutil.GetSharesAt(setsOfShares, k)
						j := rand.Intn(b)
						shamirutil.PerturbDecommitment(&shares[j])
						_ = opener.TransitionShares(shares)
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
				reconstructed := opener.Secrets()
				decommitments := opener.Decommitments()
				Expect(len(reconstructed)).To(Equal(len(secrets)))
				Expect(len(reconstructed)).To(Equal(b))
				Expect(len(decommitments)).To(Equal(b))
				for i, reconstructedSecret := range reconstructed {
					Expect(reconstructedSecret.Eq(&secrets[i])).To(BeTrue())
				}

				for j := k; j < n; j++ {
					shares := openutil.GetSharesAt(setsOfShares, j)
					_ = opener.TransitionShares(shares)
					reconstructed = opener.Secrets()
					for i, reconstructedSecret := range reconstructed {
						Expect(reconstructedSecret.Eq(&secrets[i])).To(BeTrue())
					}
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
					event := opener.TransitionReset(commitments)
					Expect(event).To(Equal(open.Aborted))
				})

				Specify("Length of commitments not equal to the batch size", func() {
					ProgressToWaitingI(rand.Intn(k - 1))

					for j := 0; j < len(commitments); j++ {
						commitments = append(commitments[:j], commitments[j+1:]...)
						Expect(func() { opener.TransitionReset(commitments) }).To(Panic())
					}
				})

				Specify("If not all commitments are for the same threshold", func() {
					ProgressToWaitingI(rand.Intn(k - 1))

					for j := 0; j < len(commitments); j++ {
						// commitment threshold is changed to < k
						commitments[j] = shamir.NewCommitmentWithCapacity(1 + rand.Intn(k-1))
						Expect(func() { opener.TransitionReset(commitments) }).To(Panic())
					}
				})

				Specify("If the commitment is for a threshold of 0", func() {
					ProgressToWaitingI(rand.Intn(k - 1))

					for j := 0; j < len(commitments); j++ {
						commitments[j] = shamir.NewCommitmentWithCapacity(0)
					}

					Expect(func() { opener.TransitionReset(commitments) }).To(Panic())
				})

				Specify("Otherwise -> Reset", func() {
					// Uninitialised
					event := opener.TransitionReset(commitments)
					Expect(event).To(Equal(open.Reset))

					// Done
					ProgressToDone()
					for i := 0; i < rand.Intn(n-k); i++ {
						shares := openutil.GetSharesAt(setsOfShares, i+k)
						_ = opener.TransitionShares(shares)
					}
					event = opener.TransitionReset(commitments)
					Expect(event).To(Equal(open.Reset))
				})
			})

			Context("Share events", func() {
				Specify("Uninitialised -> Ignored", func() {
					sharesAt0 := openutil.GetSharesAt(setsOfShares, 0)
					event := opener.TransitionShares(sharesAt0)
					Expect(event).To(Equal(open.Ignored))
				})

				Specify("Waiting -> Ignored", func() {
					i := rand.Intn(k - 1)
					ProgressToWaitingI(i)

					// delete a single share, so that len(shares) != b
					shares := openutil.GetSharesAt(setsOfShares, i)
					for j := 0; j < len(shares); j++ {
						shares = append(shares[:j], shares[j+1:]...)
						event := opener.TransitionShares(shares)
						Expect(event).To(Equal(open.Ignored))
					}
				})

				Specify("Waiting, i < k-1 -> ShareAdded", func() {
					i := rand.Intn(k - 1)
					ProgressToWaitingI(i)

					shares := openutil.GetSharesAt(setsOfShares, i)
					event := opener.TransitionShares(shares)
					Expect(event).To(Equal(open.SharesAdded))
				})

				Specify("Done -> ShareAdded", func() {
					ProgressToDone()
					for i := k; i < n; i++ {
						shares := openutil.GetSharesAt(setsOfShares, i)
						event := opener.TransitionShares(shares)
						Expect(event).To(Equal(open.SharesAdded))
					}
				})

				Specify("Waiting, i = k-1 -> Done", func() {
					ProgressToWaitingI(k - 1)
					shares := openutil.GetSharesAt(setsOfShares, k-1)
					event := opener.TransitionShares(shares)
					Expect(event).To(Equal(open.Done))
				})

				Context("Invalid shares", func() {
					Specify("Invalid share", func() {
						ProgressToWaitingI(0)

						// Index
						sharesAt0 := openutil.GetSharesAt(setsOfShares, 0)
						shamirutil.PerturbIndex(&sharesAt0[0])
						event := opener.TransitionShares(sharesAt0)
						Expect(event).To(Equal(open.InvalidShares))

						// Value
						shamirutil.PerturbValue(&sharesAt0[0])
						event = opener.TransitionShares(sharesAt0)
						Expect(event).To(Equal(open.InvalidShares))

						// Decommitment
						shamirutil.PerturbDecommitment(&sharesAt0[0])
						event = opener.TransitionShares(sharesAt0)
						Expect(event).To(Equal(open.InvalidShares))

						for i := 0; i < n; i++ {
							shares := openutil.GetSharesAt(setsOfShares, i)
							_ = opener.TransitionShares(shares)

							// Index
							j := rand.Intn(b)
							shamirutil.PerturbIndex(&shares[j])
							event := opener.TransitionShares(shares)
							Expect(event).To(Equal(open.InvalidShares))

							// Value
							shamirutil.PerturbValue(&shares[j])
							event = opener.TransitionShares(shares)
							Expect(event).To(Equal(open.InvalidShares))

							// Decommitment
							shamirutil.PerturbDecommitment(&shares[j])
							event = opener.TransitionShares(shares)
							Expect(event).To(Equal(open.InvalidShares))
						}
					})

					Specify("Duplicate share", func() {
						ProgressToWaitingI(0)
						for i := 0; i < n; i++ {
							shares := openutil.GetSharesAt(setsOfShares, i)
							_ = opener.TransitionShares(shares)

							for j := 0; j <= i; j++ {
								duplicateShares := openutil.GetSharesAt(setsOfShares, j)
								event := opener.TransitionShares(duplicateShares)
								Expect(event).To(Equal(open.IndexDuplicate))
							}
						}
					})

					Specify("Index out of range", func() {
						// To reach this case, we need a valid share that is
						// out of the normal range of indices. We thus need to
						// utilise the sharer to do this.
						indices = shamirutil.SequentialIndices(n + 1)
						for i := 0; i < b; i++ {
							setsOfShares[i] = make(shamir.VerifiableShares, n+1)
							shamir.VShareSecret(&setsOfShares[i], &commitments[i], indices, h, secrets[i], k)
						}

						// Perform the test
						ProgressToWaitingI(n)
						sharesAtN := openutil.GetSharesAt(setsOfShares, n)
						event := opener.TransitionShares(sharesAtN)
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
		b := 5
		n := 20
		k := 7

		indices := shamirutil.SequentialIndices(n)
		setsOfShares := make([]shamir.VerifiableShares, b)
		commitments := make([]shamir.Commitment, b)
		machines := make([]Machine, n)
		secrets := make([]secp256k1.Fn, b)
		for i := 0; i < b; i++ {
			setsOfShares[i] = make(shamir.VerifiableShares, n)
			commitments[i] = shamir.NewCommitmentWithCapacity(k)
			secrets[i] = secp256k1.RandomFn()
			shamir.VShareSecret(&setsOfShares[i], &commitments[i], indices, h, secrets[i], k)
		}

		ids := make([]ID, n)
		for i := range indices {
			id := ID(i)
			sharesAtI := openutil.GetSharesAt(setsOfShares, i)
			machine := newMachine(id, n, sharesAtI, commitments, open.New(uint32(b), indices, h))
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
				reconstructed := machine.(*openMachine).Secrets()
				decommitments := machine.(*openMachine).Decommitments()

				for i := 0; i < b; i++ {
					if !reconstructed[i].Eq(&secrets[i]) {
						network.Dump("test.dump")
						Fail(fmt.Sprintf("machine with ID %v got the wrong secret", machine.ID()))
					}
				}

				Expect(len(decommitments)).To(Equal(b))
			}
		})
	})
})

type shareMsg struct {
	shares   shamir.VerifiableShares
	from, to ID
}

func (msg shareMsg) From() ID { return msg.from }
func (msg shareMsg) To() ID   { return msg.to }

func (msg shareMsg) SizeHint() int {
	return msg.shares.SizeHint() + msg.from.SizeHint() + msg.to.SizeHint()
}

func (msg shareMsg) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := msg.shares.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = msg.from.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = msg.to.Marshal(buf, rem)
	return buf, rem, err
}

func (msg *shareMsg) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := msg.shares.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = msg.from.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = msg.to.Unmarshal(buf, rem)
	return buf, rem, err
}

type openMachine struct {
	id          ID
	n           int
	shares      shamir.VerifiableShares
	commitments []shamir.Commitment
	opener      open.Opener

	lastE open.ShareEvent
}

func (om openMachine) SizeHint() int {
	return om.id.SizeHint() +
		4 +
		om.shares.SizeHint() +
		surge.SizeHint(om.commitments) +
		om.opener.SizeHint()
}

func (om openMachine) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := om.id.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.MarshalU32(uint32(om.n), buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = om.shares.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(om.commitments, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = om.opener.Marshal(buf, rem)
	return buf, rem, err
}

func (om *openMachine) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := om.id.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}

	var tmp uint32
	buf, rem, err = surge.UnmarshalU32(&tmp, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	om.n = int(tmp)

	buf, rem, err = om.shares.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&om.commitments, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = om.opener.Unmarshal(buf, rem)
	return buf, rem, err
}

func newMachine(
	id ID,
	n int,
	shares shamir.VerifiableShares,
	commitments []shamir.Commitment,
	opener open.Opener,
) openMachine {
	opener.TransitionReset(commitments)
	_ = opener.TransitionShares(shares)
	lastE := open.ShareEvent(0)
	return openMachine{id, n, shares, commitments, opener, lastE}
}

func (om openMachine) Secrets() []secp256k1.Fn {
	return om.opener.Secrets()
}

func (om openMachine) Decommitments() []secp256k1.Fn {
	return om.opener.Decommitments()
}

func (om openMachine) ID() ID {
	return om.id
}

func (om openMachine) InitialMessages() []Message {
	messages := make([]Message, om.n-1)[:0]
	for i := 0; i < om.n; i++ {
		if ID(i) == om.id {
			continue
		}
		messages = append(messages, &shareMsg{
			shares: om.shares,
			from:   om.id,
			to:     ID(i),
		})
	}
	return messages
}

func (om *openMachine) Handle(msg Message) []Message {
	switch msg := msg.(type) {
	case *shareMsg:
		om.lastE = om.opener.TransitionShares(msg.shares)
		return nil

	default:
		panic("unexpected message")
	}
}
