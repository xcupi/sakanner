package sstiactive

import (
	"bytes"
	"crypto/rand"
	"math/big"
)

// operandPrimes is a small, fixed pool of 2-digit primes -- large
// enough that a randomly chosen pair's product is a 3-4 digit number
// with negligible chance of coincidentally already appearing in a
// target's normal response content, small enough that the arithmetic
// stays trivially within any real template engine's own expression
// evaluator (this is deliberately NOT an attempt at code execution --
// only arithmetic evaluation, sufficient to prove template expression
// evaluation genuinely occurred).
var operandPrimes = []int{11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47}

// randomOperands returns two DISTINCT primes from operandPrimes,
// freshly chosen per call via crypto/rand -- mirrors
// cmdinjectionactive's own "freshly generated, unpredictable
// per-probe value" precedent (there, a UUID token; here, an operand
// pair), so the resulting product can never be guessed or reused
// across probes/targets.
func randomOperands() (a, b int) {
	i := randIndex(len(operandPrimes))
	j := randIndex(len(operandPrimes) - 1)
	if j >= i {
		j++
	}
	return operandPrimes[i], operandPrimes[j]
}

func randIndex(n int) int {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

// isDigit reports whether b is an ASCII decimal digit.
func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

// containsIsolatedNumber reports whether body contains numStr as a
// STANDALONE numeric token -- not merely as a substring of a LARGER
// number (e.g. numStr "358" must not match inside "13589" or
// "3580"). This is the exact-match discipline every other
// "-active" detector in this codebase applies to its own marker --
// here the "marker" is an arithmetic result no legitimate response
// would produce coincidentally, but the boundary check still matters:
// a truncated/partial numeric match is never sufficient proof.
func containsIsolatedNumber(body []byte, numStr string) bool {
	if numStr == "" {
		return false
	}
	target := []byte(numStr)
	for start := 0; start <= len(body); {
		idx := bytes.Index(body[start:], target)
		if idx < 0 {
			return false
		}
		pos := start + idx
		beforeOK := pos == 0 || !isDigit(body[pos-1])
		afterPos := pos + len(target)
		afterOK := afterPos >= len(body) || !isDigit(body[afterPos])
		if beforeOK && afterOK {
			return true
		}
		start = pos + 1
	}
	return false
}
