package rkpg_test

import (
	"math/rand"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/mpc/rkpg"
	"github.com/renproject/mpc/rkpg/rkpgutil"
	"github.com/renproject/shamir"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir/shamirutil"
)

var _ = Describe("RKPG", func() {
	rand.Seed(int64(time.Now().Nanosecond()))
	trials := 10

	RandomTestParams := func() (int, int, int, int, secp256k1.Point, []secp256k1.Fn, Params, State) {
		k := shamirutil.RandRange(4, 15)
		n := 3 * k
		t := k - 2
		b := shamirutil.RandRange(2, 10)
		h := secp256k1.RandomPoint()
		indices := shamirutil.RandomIndices(n)
		params := CreateParams(k, b, h, indices)
		state := NewState(n, b)
		return n, k, t, b, h, indices, params, state
	}

	Context("state transitions", func() {
		RXGOutputs := func(k, b int, indices []secp256k1.Fn, h secp256k1.Point) (
			[]shamir.VerifiableShares,
			[]shamir.VerifiableShares,
			[]shamir.Commitment,
		) {
			rngShares, rngComs := rkpgutil.RNGOutputBatch(indices, k, b, h)
			rzgShares, _ := rkpgutil.RZGOutputBatch(indices, k, b, h)
			return rngShares, rzgShares, rngComs
		}

		CreateInvalidShares := func(
			n, t, b int,
			params *Params,
			rngShares, rzgShares []shamir.VerifiableShares,
		) []shamir.Shares {
			var err error
			shares := make([]shamir.Shares, n)
			for i := range shares {
				shares[i], err = InitialMessages(params, rngShares[i], rzgShares[i])
				Expect(err).ToNot(HaveOccurred())
			}

			badBuf := rand.Intn(b)
			for i := 0; i < t; i++ {
				shares[i][badBuf] = shamir.NewShare(shares[i][badBuf].Index(), secp256k1.NewFnFromU16(0))
			}

			return shares
		}

		CheckAgainstInvalidShares := func(
			n, k int,
			state *State,
			params *Params,
			shares []shamir.Shares,
			coms []shamir.Commitment,
		) {
			threshold := n - k + 1
			errThreshold := n - 2
			for i := 0; i < threshold-1; i++ {
				res, e := TransitionShares(state, params, coms, shares[i])
				Expect(e).To(Equal(ShareAdded))
				Expect(res).To(BeNil())
			}
			for i := threshold - 1; i < errThreshold-1; i++ {
				res, e := TransitionShares(state, params, coms, shares[i])
				Expect(e).To(Equal(TooManyErrors))
				Expect(res).To(BeNil())
			}
			res, e := TransitionShares(state, params, coms, shares[errThreshold-1])
			Expect(res).ToNot(BeNil())
			Expect(e).To(Equal(Reconstructed))
		}

		Specify("shares with invalid batch size", func() {
			for i := 0; i < trials; i++ {
				_, _, _, b, _, _, params, state := RandomTestParams()
				shares := make(shamir.Shares, b)

				res, e := TransitionShares(&state, &params, []shamir.Commitment{}, shares[:b-1])
				Expect(res).To(BeNil())
				Expect(e).To(Equal(WrongBatchSize))
			}
		})

		Specify("shares with invalid index", func() {
			for i := 0; i < trials; i++ {
				_, _, _, b, _, _, params, state := RandomTestParams()
				shares := make(shamir.Shares, b)

				// As it is an uninitialised slice, all of the shares in
				// `shares` should have index zero, which should not be in the
				// set `indices` with overwhelming probability.
				res, e := TransitionShares(&state, &params, []shamir.Commitment{}, shares)
				Expect(res).To(BeNil())
				Expect(e).To(Equal(InvalidIndex))
			}
		})

		Specify("shares with duplicate indices", func() {
			for i := 0; i < trials; i++ {
				_, _, _, b, _, indices, params, state := RandomTestParams()
				shares := make(shamir.Shares, b)

				for i := range shares {
					shares[i] = shamir.NewShare(indices[0], secp256k1.Fn{})
				}

				_, _ = TransitionShares(&state, &params, []shamir.Commitment{}, shares)
				res, e := TransitionShares(&state, &params, []shamir.Commitment{}, shares)
				Expect(res).To(BeNil())
				Expect(e).To(Equal(DuplicateIndex))
			}
		})

		Specify("shares with inconsistent indices", func() {
			for i := 0; i < trials; i++ {
				_, _, _, b, _, indices, params, state := RandomTestParams()
				shares := make(shamir.Shares, b)

				shares[0] = shamir.NewShare(indices[0], secp256k1.Fn{})
				for i := 1; i < len(shares); i++ {
					shares[i] = shamir.NewShare(indices[1], secp256k1.Fn{})
				}

				res, e := TransitionShares(&state, &params, []shamir.Commitment{}, shares)
				Expect(res).To(BeNil())
				Expect(e).To(Equal(InconsistentShares))
			}
		})

		Specify("valid shares", func() {
			for i := 0; i < trials; i++ {
				n, k, _, b, h, indices, params, state := RandomTestParams()
				rngShares, rzgShares, rngComs := RXGOutputs(k, b, indices, h)

				var err error
				shares := make([]shamir.Shares, n)
				for i := range shares {
					shares[i], err = InitialMessages(&params, rngShares[i], rzgShares[i])
					Expect(err).ToNot(HaveOccurred())
				}

				threshold := n - k + 1
				for i := 0; i < threshold-1; i++ {
					res, e := TransitionShares(&state, &params, rngComs, shares[i])
					Expect(e).To(Equal(ShareAdded))
					Expect(res).To(BeNil())
				}
				res, e := TransitionShares(&state, &params, rngComs, shares[threshold-1])
				Expect(res).ToNot(BeNil())
				Expect(e).To(Equal(Reconstructed))
			}
		})

		Specify("invalid shares", func() {
			for i := 0; i < trials; i++ {
				n, k, t, b, h, indices, params, state := RandomTestParams()
				rngShares, rzgShares, rngComs := RXGOutputs(k, b, indices, h)

				shares := CreateInvalidShares(n, t, b, &params, rngShares, rzgShares)
				CheckAgainstInvalidShares(n, k, &state, &params, shares, rngComs)
			}
		})

		Specify("the state object can be reused", func() {
			for i := 0; i < trials; i++ {
				n, k, t, b, h, indices, params, state := RandomTestParams()
				rngShares, rzgShares, rngComs := RXGOutputs(k, b, indices, h)

				shares := CreateInvalidShares(n, t, b, &params, rngShares, rzgShares)
				CheckAgainstInvalidShares(n, k, &state, &params, shares, rngComs)

				state.Clear()
				CheckAgainstInvalidShares(n, k, &state, &params, shares, rngComs)
			}
		})
	})

	Context("initial messages", func() {
		Specify("shares with the wrong batch size", func() {
			for i := 0; i < trials; i++ {
				_, _, _, b, _, _, params, _ := RandomTestParams()
				rngShares := make(shamir.VerifiableShares, b)
				rzgShares := make(shamir.VerifiableShares, b)

				_, err := InitialMessages(&params, rngShares[:b-1], rzgShares)
				Expect(err).To(HaveOccurred())
				_, err = InitialMessages(&params, rngShares, rzgShares[:b-1])
				Expect(err).To(HaveOccurred())
				_, err = InitialMessages(&params, rngShares[:b-1], rzgShares[:b-1])
				Expect(err).To(HaveOccurred())
			}
		})

		Specify("inconsistent share indices", func() {
			for i := 0; i < trials; i++ {
				_, _, _, b, _, _, params, _ := RandomTestParams()
				rngShares := make(shamir.VerifiableShares, b)
				rzgShares := make(shamir.VerifiableShares, b)

				rngShares[0] = shamir.NewVerifiableShare(
					shamir.NewShare(secp256k1.RandomFn(), secp256k1.Fn{}),
					secp256k1.Fn{},
				)
				_, err := InitialMessages(&params, rngShares, rzgShares)
				Expect(err).To(HaveOccurred())
			}
		})

		Specify("shares with invalid indices", func() {
			for i := 0; i < trials; i++ {
				_, _, _, b, _, _, params, _ := RandomTestParams()
				rngShares := make(shamir.VerifiableShares, b)
				rzgShares := make(shamir.VerifiableShares, b)

				_, err := InitialMessages(&params, rngShares, rzgShares)
				Expect(err).To(HaveOccurred())
			}
		})
	})
})
