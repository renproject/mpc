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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/mpc/mpcutil"
)

// The main properties that we want to test for the Opener state machine are
//
//	1. The state transition logic is as described in the documentation.
//	2. Once enough valid shares have been received for construction, the
//	correct share is reconstructed.
//	4. In a network of n nodes, each holding a share of a secret, all honest
//	nodes will eventually be able to reconstruct the secret in the presence of
//	n-k malicious nodes where k is the reconstruction threshold of the secret.
var _ = Describe("Opener", func() {
	rand.Seed(int64(time.Now().Nanosecond()))

	// Pedersen commitment system parameter. For testing this can be random,
	// but in a real world use case this should be chosen appropriately.
	h := secp256k1.RandomPoint()

	TransposeShares := func(shares []shamir.VerifiableShares) []shamir.VerifiableShares {
		numRows := len(shares)
		numCols := len(shares[0])
		transposed := make([]shamir.VerifiableShares, numCols)
		for i := range transposed {
			transposed[i] = make(shamir.VerifiableShares, numRows)
			for j := range transposed[i] {
				transposed[i][j] = shares[j][i]
			}
		}
		return transposed
	}

	Describe("Properties", func() {
		b := 5
		n := 20
		k := 7

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

			sharingsBatch := make([]shamir.VerifiableShares, b)
			commitments := make([]shamir.Commitment, b)
			for i := 0; i < b; i++ {
				sharingsBatch[i] = make(shamir.VerifiableShares, n)
				commitments[i] = shamir.NewCommitmentWithCapacity(k)
				shamir.VShareSecret(&sharingsBatch[i], &commitments[i], indices, h, secrets[i], k)
			}
			shareBatchesByPlayer := TransposeShares(sharingsBatch)

			opener := open.New(commitments, indices, h)

			return indices, opener, secrets, shareBatchesByPlayer, commitments
		}

		ProgressToWaitingI := func(opener *open.Opener, setsOfShares []shamir.VerifiableShares, i int) (
			[]secp256k1.Fn, []secp256k1.Fn,
		) {
			var secrets, decommitments []secp256k1.Fn
			for j := 0; j < i; j++ {
				secrets, decommitments, _ = opener.HandleShareBatch(setsOfShares[j])
			}
			return secrets, decommitments
		}

		ProgressToDone := func(opener *open.Opener, setsOfShares []shamir.VerifiableShares) (
			[]secp256k1.Fn, []secp256k1.Fn,
		) {
			return ProgressToWaitingI(opener, setsOfShares, k)
		}

		//
		// State transition logic
		//

		Context("State transitions (1)", func() {
			Context("Waiting State", func() {
				Specify("(i < k-1) Share, Valid(c) -> Waiting(c, k, i+1)", func() {
					_, opener, _, setsOfShares, _ := Setup()
					i := rand.Intn(k - 1)
					ProgressToWaitingI(&opener, setsOfShares, i)
					shares := setsOfShares[i]
					_, _, _ = opener.HandleShareBatch(shares)
					Expect(opener.I()).To(Equal(i + 1))
				})

				Specify("(i = k-1) Share, Valid(c) -> Done(c)", func() {
					_, opener, _, setsOfShares, _ := Setup()
					ProgressToWaitingI(&opener, setsOfShares, k-1)
					shares := setsOfShares[k-1]
					_, _, _ = opener.HandleShareBatch(shares)
					Expect(opener.I() >= k).To(BeTrue())
				})

				Context("Share, not Valid(c) -> Do nothing", func() {
					Specify("wrong index", func() {
						_, opener, _, setsOfShares, _ := Setup()
						// progress till i
						i := rand.Intn(k)
						ProgressToWaitingI(&opener, setsOfShares, i)

						// perturb a random share from `sharesAtI`
						shares := setsOfShares[i]
						j := rand.Intn(b)
						shamirutil.PerturbIndex(&shares[j])
						_, _, _ = opener.HandleShareBatch(shares)
						Expect(opener.I()).To(Equal(i))
					})
					Specify("wrong value", func() {
						_, opener, _, setsOfShares, _ := Setup()
						i := rand.Intn(k)
						ProgressToWaitingI(&opener, setsOfShares, i)

						shares := setsOfShares[i]
						j := rand.Intn(b)
						shamirutil.PerturbValue(&shares[j])
						_, _, _ = opener.HandleShareBatch(shares)
						Expect(opener.I()).To(Equal(i))
					})

					Specify("wrong decommitment", func() {
						_, opener, _, setsOfShares, _ := Setup()
						i := rand.Intn(k)
						ProgressToWaitingI(&opener, setsOfShares, i)

						shares := setsOfShares[i]
						j := rand.Intn(b)
						shamirutil.PerturbDecommitment(&shares[j])
						_, _, _ = opener.HandleShareBatch(shares)
						Expect(opener.I()).To(Equal(i))
					})
				})
			})

			Context("Done State", func() {
				Specify("Share, Valid(c) -> Do Nothing", func() {
					_, opener, _, setsOfShares, _ := Setup()
					ProgressToDone(&opener, setsOfShares)
					shares := setsOfShares[k]
					_, _, _ = opener.HandleShareBatch(shares)
					Expect(opener.I()).To(Equal(k + 1))
				})

				Context("Share, not Valid(c) -> Do nothing", func() {
					Specify("wrong index", func() {
						_, opener, _, setsOfShares, _ := Setup()
						ProgressToDone(&opener, setsOfShares)
						shares := setsOfShares[k]
						j := rand.Intn(b)
						shamirutil.PerturbIndex(&shares[j])
						_, _, _ = opener.HandleShareBatch(shares)
						Expect(opener.I()).To(Equal(k))
					})

					Specify("wrong value", func() {
						_, opener, _, setsOfShares, _ := Setup()
						ProgressToDone(&opener, setsOfShares)
						shares := setsOfShares[k]
						j := rand.Intn(b)
						shamirutil.PerturbValue(&shares[j])
						_, _, _ = opener.HandleShareBatch(shares)
						Expect(opener.I()).To(Equal(k))
					})

					Specify("wrong decommitment", func() {
						_, opener, _, setsOfShares, _ := Setup()
						ProgressToDone(&opener, setsOfShares)
						shares := setsOfShares[k]
						j := rand.Intn(b)
						shamirutil.PerturbDecommitment(&shares[j])
						_, _, _ = opener.HandleShareBatch(shares)
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
				_, opener, secrets, setsOfShares, _ := Setup()
				reconstructed, decommitments := ProgressToDone(&opener, setsOfShares)
				Expect(len(reconstructed)).To(Equal(len(secrets)))
				Expect(len(reconstructed)).To(Equal(b))
				Expect(len(decommitments)).To(Equal(b))
				for i, reconstructedSecret := range reconstructed {
					Expect(reconstructedSecret.Eq(&secrets[i])).To(BeTrue())
				}

				for j := k; j < n; j++ {
					shares := setsOfShares[j]
					_, reconstructed, _ = opener.HandleShareBatch(shares)
					for i, reconstructedSecret := range reconstructed {
						Expect(reconstructedSecret.Eq(&secrets[i])).To(BeTrue())
					}
				}
			})
		})

		//
		// Errors
		//

		Context("errors", func() {
			Specify("incorrect batch size", func() {
				_, opener, _, setsOfShares, _ := Setup()
				i := rand.Intn(k - 1)
				ProgressToWaitingI(&opener, setsOfShares, i)

				// delete a single share, so that len(shares) != b
				shares := setsOfShares[i]
				for j := 0; j < len(shares); j++ {
					shares = append(shares[:j], shares[j+1:]...)
					_, _, err := opener.HandleShareBatch(shares)
					Expect(err).To(Equal(open.ErrIncorrectBatchSize))
				}
			})

			// FIXME: This is not an error case, move somewhere else.
			Specify("Waiting, i < k-1 -> ShareAdded", func() {
				_, opener, secrets, setsOfShares, _ := Setup()
				i := rand.Intn(k - 1)
				ProgressToWaitingI(&opener, setsOfShares, i)

				shares := setsOfShares[i]
				secrets, decommitments, err := opener.HandleShareBatch(shares)
				Expect(err).ToNot(HaveOccurred())
				Expect(secrets).To(BeNil())
				Expect(decommitments).To(BeNil())
			})

			// FIXME: This is not an error case, move somewhere else.
			Specify("Done -> ShareAdded", func() {
				_, opener, _, setsOfShares, _ := Setup()
				ProgressToDone(&opener, setsOfShares)
				for i := k; i < n; i++ {
					shares := setsOfShares[i]
					secrets, decommitments, err := opener.HandleShareBatch(shares)
					Expect(err).ToNot(HaveOccurred())
					Expect(secrets).To(BeNil())
					Expect(decommitments).To(BeNil())
				}
			})

			// FIXME: This is not an error case, move somewhere else.
			Specify("Waiting, i = k-1 -> Done", func() {
				_, opener, secrets, setsOfShares, _ := Setup()
				ProgressToWaitingI(&opener, setsOfShares, k-1)
				shares := setsOfShares[k-1]
				secrets, decommitments, err := opener.HandleShareBatch(shares)
				Expect(err).ToNot(HaveOccurred())
				Expect(secrets).ToNot(BeNil())
				Expect(decommitments).ToNot(BeNil())
			})

			Context("invalid shares", func() {
				Specify("Invalid share", func() {
					_, opener, _, setsOfShares, _ := Setup()
					ProgressToWaitingI(&opener, setsOfShares, 0)

					// Index
					sharesAt0 := setsOfShares[0]
					shamirutil.PerturbIndex(&sharesAt0[0])
					_, _, err := opener.HandleShareBatch(sharesAt0)
					Expect(err).To(Equal(open.ErrInvalidShares))

					// Value
					shamirutil.PerturbValue(&sharesAt0[0])
					_, _, err = opener.HandleShareBatch(sharesAt0)
					Expect(err).To(Equal(open.ErrInvalidShares))

					// Decommitment
					shamirutil.PerturbDecommitment(&sharesAt0[0])
					_, _, err = opener.HandleShareBatch(sharesAt0)
					Expect(err).To(Equal(open.ErrInvalidShares))

					for i := 0; i < n; i++ {
						shares := setsOfShares[i]
						_, _, _ = opener.HandleShareBatch(shares)

						// Index
						j := rand.Intn(b)
						shamirutil.PerturbIndex(&shares[j])
						_, _, err := opener.HandleShareBatch(shares)
						Expect(err).To(Equal(open.ErrInvalidShares))

						// Value
						shamirutil.PerturbValue(&shares[j])
						_, _, err = opener.HandleShareBatch(shares)
						Expect(err).To(Equal(open.ErrInvalidShares))

						// Decommitment
						shamirutil.PerturbDecommitment(&shares[j])
						_, _, err = opener.HandleShareBatch(shares)
						Expect(err).To(Equal(open.ErrInvalidShares))
					}
				})

				Specify("Duplicate share", func() {
					_, opener, _, setsOfShares, _ := Setup()
					ProgressToWaitingI(&opener, setsOfShares, 0)
					for i := 0; i < n; i++ {
						shares := setsOfShares[i]
						_, _, _ = opener.HandleShareBatch(shares)

						for j := 0; j <= i; j++ {
							duplicateShares := setsOfShares[j]
							_, _, err := opener.HandleShareBatch(duplicateShares)
							Expect(err).To(Equal(open.ErrDuplicateIndex))
						}
					}
				})

				Specify("Index out of range", func() {
					indices := shamirutil.SequentialIndices(n + 1)
					secrets := make([]secp256k1.Fn, b)
					for i := 0; i < b; i++ {
						secrets[i] = secp256k1.RandomFn()
					}
					commitments := make([]shamir.Commitment, b)
					sharingsBatch := make([]shamir.VerifiableShares, b)
					for i := 0; i < b; i++ {
						sharingsBatch[i] = make(shamir.VerifiableShares, n+1)
						commitments[i] = shamir.NewCommitmentWithCapacity(k)
						shamir.VShareSecret(&sharingsBatch[i], &commitments[i], indices, h, secrets[i], k)
					}
					shareBatchesByPlayer := TransposeShares(sharingsBatch)
					opener := open.New(commitments, indices[:n], h)

					ProgressToWaitingI(&opener, shareBatchesByPlayer, n)
					sharesAtN := shareBatchesByPlayer[n]
					_, _, err := opener.HandleShareBatch(sharesAtN)
					Expect(err).To(Equal(open.ErrIndexOutOfRange))
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
		sharingsBatch := make([]shamir.VerifiableShares, b)
		commitments := make([]shamir.Commitment, b)
		machines := make([]Machine, n)
		secrets := make([]secp256k1.Fn, b)
		for i := 0; i < b; i++ {
			sharingsBatch[i] = make(shamir.VerifiableShares, n)
			commitments[i] = shamir.NewCommitmentWithCapacity(k)
			secrets[i] = secp256k1.RandomFn()
			shamir.VShareSecret(&sharingsBatch[i], &commitments[i], indices, h, secrets[i], k)
		}
		shareBatchesByPlayer := TransposeShares(sharingsBatch)

		ids := make([]ID, n)
		for i := range indices {
			id := ID(i)
			sharesAtI := shareBatchesByPlayer[i]
			machine := openutil.NewMachine(id, uint32(n), sharesAtI, commitments,
				open.New(commitments, indices, h))
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
				reconstructed := machine.(*openutil.Machine).Secrets
				decommitments := machine.(*openutil.Machine).Decommitments

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
