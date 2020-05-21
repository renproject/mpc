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
