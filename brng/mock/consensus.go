package mock

import (
	"github.com/renproject/mpc/brng"
	"github.com/renproject/secp256k1-go"
	"github.com/renproject/shamir"
)

type PullConsensus struct {
	done          bool
	honestIndices []secp256k1.Secp256k1N
	threshold     int
	table         brng.Table
	checker       shamir.VSSChecker
}

func (pc *PullConsensus) HandleRow(row brng.Row) bool {
	if pc.done {
		return true
	}

	for _, sharing := range row {
		for _, index := range pc.honestIndices {
			// Only check the share corresponding to the leader index; in
			// practice the shares will be encrypted for each party and so the
			// leader can only check their own indices.
			share, err := sharing.ShareWithIndex(index)
			if err != nil {
				panic("row should contain all honest indices")
			}

			c := sharing.Commitment()
			if !pc.checker.IsValid(&c, &share) {
				return pc.done
			}
		}
	}

	pc.table = append(pc.table, row)
	if len(pc.table) == pc.threshold {
		pc.done = true
	}

	return pc.done
}

func (pc PullConsensus) TableIsValid() bool {
	for _, row := range pc.table {
		for _, sharing := range row {
			for _, index := range pc.honestIndices {
				// Only check the share corresponding to the leader index; in
				// practice the shares will be encrypted for each party and so the
				// leader can only check their own indices.
				share, err := sharing.ShareWithIndex(index)
				if err != nil {
					panic("row should contain all honest indices")
				}

				c := sharing.Commitment()
				if !pc.checker.IsValid(&c, &share) {
					return false
				}
			}
		}
	}

	return true
}
