package luks

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

// GeneratePassphrase generates a word-based passphrase with at least minWords
// words and a minimum total length of 32 characters.
// Format: "Apple-Tower-Kitchen-Forest" (capitalized, hyphen-separated).
func GeneratePassphrase(minWords int) (string, error) {
	if minWords < 3 {
		minWords = 3
	}

	var words []string
	for {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(wordList))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random index: %w", err)
		}
		words = append(words, wordList[idx.Int64()])

		passphrase := strings.Join(words, "-")
		if len(words) >= minWords && len(passphrase) >= 32 {
			return passphrase, nil
		}
	}
}
