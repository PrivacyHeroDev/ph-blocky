package stats

import (
	"testing"

	"github.com/privacyherodev/ph-blocky/log"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestStats(t *testing.T) {
	log.NewLogger("Warn", "text")
	RegisterFailHandler(Fail)
	RunSpecs(t, "Stats Suite")
}
