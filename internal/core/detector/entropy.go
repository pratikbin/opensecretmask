package detector

import "math"

type EntropyScanner struct {
	threshold float64
	minLen    int
}

func NewEntropyScanner(threshold float64, minLen int) *EntropyScanner {
	return &EntropyScanner{threshold: threshold, minLen: minLen}
}

// ScoreToken returns Shannon entropy in bits/char. >= threshold means "secret-like".
func (s *EntropyScanner) ScoreToken(t string) float64 {
	if len(t) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(t); i++ {
		counts[t[i]]++
	}
	n := float64(len(t))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func (s *EntropyScanner) IsSecret(t string) bool {
	if len(t) < s.minLen {
		return false
	}
	return s.ScoreToken(t) >= s.threshold
}
