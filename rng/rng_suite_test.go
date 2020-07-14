package rng_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestRng(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Rng Suite")
}
