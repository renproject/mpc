package rkpg_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestRkpg(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Rkpg Suite")
}
