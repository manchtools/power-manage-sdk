package encryption

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

// randInt is a seam over crypto/rand.Int so the (practically unreachable)
// RNG-failure path is exercisable in tests.
var randInt = rand.Int

// GeneratePassphrase generates a word-based passphrase as a Secret: at least
// minWords (minimum 3) capitalized words joined by '-', and at least 32 chars
// total. Example: "Apple-Tower-Kitchen-Forest".
func GeneratePassphrase(minWords int) (exec.Secret, error) {
	if minWords < 3 {
		minWords = 3
	}
	var words []string
	for {
		idx, err := randInt(rand.Reader, big.NewInt(int64(len(wordList))))
		if err != nil {
			return exec.Secret{}, fmt.Errorf("generate random index: %w", err)
		}
		words = append(words, wordList[idx.Int64()])
		phrase := strings.Join(words, "-")
		if len(words) >= minWords && len(phrase) >= 32 {
			// The wordlist + '-' contain no newline/CR, so NewSecret cannot reject.
			return exec.NewSecret(phrase)
		}
	}
}
