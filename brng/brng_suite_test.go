package brng_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestBrng(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Brng Suite")
}
