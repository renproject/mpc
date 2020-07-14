package compute_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestCompute(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Compute Suite")
}
