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

	PerturbRandomShareInBatch := func(shareBatch shamir.VerifiableShares) shamir.VerifiableShares {
		r := rand.Uint32()
		// Make sure that we always perturb.
		doAll := r&0b111 == 0

		perturbedBatch := make(shamir.VerifiableShares, len(shareBatch))
		copy(perturbedBatch, shareBatch)
		i := rand.Intn(len(perturbedBatch))
		if r&0b001 != 0 || doAll {
			perturbedBatch[i].Share.Index = secp256k1.RandomFn()
		}
		if r&0b010 != 0 || doAll {
			perturbedBatch[i].Share.Value = secp256k1.RandomFn()
		}
		if r&0b100 != 0 || doAll {
			perturbedBatch[i].Decommitment = secp256k1.RandomFn()
		}

		return perturbedBatch
	}

	Describe("Properties", func() {
		b := 5
		n := 20
		k := 7

		Setup := func(n, k, b int) (
			[]secp256k1.Fn,
			open.Opener,
			[]secp256k1.Fn,
			[]shamir.VerifiableShares,
			[]shamir.Commitment,
		) {
			indices := shamirutil.SequentialIndices(n)
			sharingsBatch := make([]shamir.VerifiableShares, b)
			commitments := make([]shamir.Commitment, b)
			secrets := make([]secp256k1.Fn, b)
			for i := 0; i < b; i++ {
				sharingsBatch[i] = make(shamir.VerifiableShares, n)
				commitments[i] = shamir.NewCommitmentWithCapacity(k)
				secrets[i] = secp256k1.RandomFn()
				shamir.VShareSecret(&sharingsBatch[i], &commitments[i], indices, h, secrets[i], k)
			}
			shareBatchesByPlayer := TransposeShares(sharingsBatch)
			opener := open.New(commitments, indices, h)
			return indices, opener, secrets, shareBatchesByPlayer, commitments
		}

		CheckInvalidBatchBehaviour := func(
			opener *open.Opener, invalidBatch shamir.VerifiableShares, err error,
		) {
			initialBufCount := opener.I()
			secrets, decommitments, err := opener.HandleShareBatch(invalidBatch)
			Expect(secrets).To(BeNil())
			Expect(decommitments).To(BeNil())
			Expect(err).To(Equal(err))
			Expect(opener.I()).To(Equal(initialBufCount))
		}

		Context("state transitions", func() {
			It("should add the share to the buffer if it is valid", func() {
				_, opener, secrets, shareBatchesByPlayer, _ := Setup(n, k, b)

				for i, shareBatch := range shareBatchesByPlayer {
					reconstructedSecrets, decommitments, err := opener.HandleShareBatch(shareBatch)
					Expect(err).ToNot(HaveOccurred())
					Expect(opener.I()).To(Equal(i + 1))
					if opener.I() == k {
						Expect(reconstructedSecrets).ToNot(BeNil())
						Expect(decommitments).ToNot(BeNil())
						Expect(len(reconstructedSecrets)).To(Equal(len(secrets)))
						Expect(len(reconstructedSecrets)).To(Equal(b))
						Expect(len(decommitments)).To(Equal(b))
						for i, secret := range reconstructedSecrets {
							Expect(secret.Eq(&secrets[i])).To(BeTrue())
						}
						// TODO: Check decommitments too?
					} else {
						Expect(reconstructedSecrets).To(BeNil())
						Expect(decommitments).To(BeNil())
					}
				}
			})

			It("should return an error when the share batch is invalid", func() {
				indices, _, _, shareBatchesByPlayerEx, commitmentBatch := Setup(n+1, k, b)
				opener := open.New(commitmentBatch, indices[:len(indices)-1], h)
				shareBatchesByPlayer := shareBatchesByPlayerEx[:len(shareBatchesByPlayerEx)-1]
				extraShareBatch := shareBatchesByPlayerEx[len(shareBatchesByPlayerEx)-1]

				for i, shareBatch := range shareBatchesByPlayer {
					// Share batch with the wrong batch size.
					CheckInvalidBatchBehaviour(&opener, shareBatch[1:], open.ErrIncorrectBatchSize)

					// Share batch with invalid index/value/decommitment.
					invalidBatch := PerturbRandomShareInBatch(shareBatch)
					CheckInvalidBatchBehaviour(&opener, invalidBatch, open.ErrInvalidShares)

					_, _, _ = opener.HandleShareBatch(shareBatch)
					Expect(opener.I()).To(Equal(i + 1))

					// Share batch with an index that has already been handled.
					CheckInvalidBatchBehaviour(&opener, shareBatch, open.ErrDuplicateIndex)
				}

				// Otherwise valid share batch that has an index outside of the
				// perscribed index set.
				CheckInvalidBatchBehaviour(&opener, extraShareBatch, open.ErrIndexOutOfRange)
			})
		})

		Context("panics", func() {
			Specify("invalid batch size", func() {
				indices := []secp256k1.Fn{}
				Expect(func() { open.New([]shamir.Commitment{}, indices, h) }).To(Panic())
			})

			Specify("invalid reconstruction threshold (k)", func() {
				indices := []secp256k1.Fn{}
				Expect(func() { open.New(make([]shamir.Commitment, b), indices, h) }).To(Panic())
			})

			Specify("commitment batch with inconsistent reconstruction thresholds", func() {
				indices := []secp256k1.Fn{}
				commitmentBatch := make([]shamir.Commitment, b)
				for i := range commitmentBatch {
					commitmentBatch[i].Append(secp256k1.RandomPoint())
				}
				// First commitment will have k = 2, others will have k = 1.
				commitmentBatch[0].Append(secp256k1.RandomPoint())
				Expect(func() { open.New(commitmentBatch, indices, h) }).To(Panic())
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
