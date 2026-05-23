package detect

import "math"

// shannon returns the Shannon entropy of s in bits per character.
func shannon(s []byte) float64 {
	if len(s) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range s {
		freq[b]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// entropyTokens splits body into secret-shaped tokens and returns those at
// least minLen bytes long with Shannon entropy of at least threshold.
func entropyTokens(body []byte, threshold float64, minLen int) []string {
	var out []string
	start := -1
	for i := 0; i <= len(body); i++ {
		if i < len(body) && isTokenByte(body[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			// Check length before converting to string — a sub-minLen token
			// never qualifies, so skip the allocation entirely.
			if tok := body[start:i]; len(tok) >= minLen && shannon(tok) >= threshold {
				out = append(out, string(tok))
			}
			start = -1
		}
	}
	return out
}

// isTokenByte reports whether b can be part of a secret-shaped token.
func isTokenByte(b byte) bool {
	switch {
	case b >= '0' && b <= '9', b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z':
		return true
	case b == '-', b == '_', b == '.', b == '+', b == '/', b == '=':
		return true
	}
	return false
}
