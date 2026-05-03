package transformer

import (
	"errors"
	"fmt"
	"io"
	"regexp"
)

var ErrMaskExhaustedRetries = errors.New("opensecretmask: collision retries exhausted (8); aborting to avoid weak mask")

const maxCollisionRetries = 8

// Hasher is the minimal interface Mask requires from keymgr.
// keymgr.Hasher implements this — its Stream(info []byte) returns io.Reader.
type Hasher interface {
	Stream(info []byte) io.Reader
}

type Segment struct {
	Name    string
	Group   int
	Charset Charset
}

type Rule struct {
	ID          string
	Pattern     *regexp.Regexp
	MinLen      int
	MaxLen      int
	BeginMarker string
	EndMarker   string
	PrefixLen   int
	Charset     Charset
	Segments    []Segment
}

// Mask produces a format-preserving mask for `real` according to `rule`.
// `existing` is mappings.by_mask for cross-secret collision check.
func Mask(real string, rule Rule, hasher Hasher, existing map[string]string) (string, error) {
	if rule.Segments != nil {
		return maskSegments(real, rule, hasher, existing)
	}
	return maskFlat(real, rule, hasher, existing)
}

func maskFlat(real string, rule Rule, hasher Hasher, existing map[string]string) (string, error) {
	if len(real) < rule.PrefixLen {
		return "", fmt.Errorf("real value shorter than rule.PrefixLen (%d < %d)", len(real), rule.PrefixLen)
	}
	prefix := real[:rule.PrefixLen]
	bodyLen := len(real) - rule.PrefixLen
	cs := rule.Charset.Bytes()

	for attempt := 0; attempt < maxCollisionRetries; attempt++ {
		body, err := deriveCharsetBytes(hasher, []byte(real), attempt, bodyLen, cs)
		if err != nil {
			return "", fmt.Errorf("mask body derivation failed: %w", err)
		}
		masked := prefix + string(body)
		if masked == real {
			continue
		}
		if other, exists := existing[masked]; exists && other != real {
			continue
		}
		return masked, nil
	}
	return "", ErrMaskExhaustedRetries
}

func maskSegments(real string, rule Rule, hasher Hasher, existing map[string]string) (string, error) {
	locs := rule.Pattern.FindStringSubmatchIndex(real)
	if locs == nil {
		return "", fmt.Errorf("rule %q did not match the input it was supposed to", rule.ID)
	}
	out := []byte(real)
	type span struct {
		start, end int
		cs         []byte
	}
	var spans []span
	for _, seg := range rule.Segments {
		if 2*seg.Group+1 >= len(locs) {
			return "", fmt.Errorf("segment %q (group %d) out of range", seg.Name, seg.Group)
		}
		s, e := locs[2*seg.Group], locs[2*seg.Group+1]
		if s < 0 {
			return "", fmt.Errorf("segment %q (group %d) did not capture", seg.Name, seg.Group)
		}
		spans = append(spans, span{s, e, seg.Charset.Bytes()})
	}
	for i := 0; i < len(spans); i++ {
		for j := i + 1; j < len(spans); j++ {
			if spans[j].start > spans[i].start {
				spans[i], spans[j] = spans[j], spans[i]
			}
		}
	}
	for attempt := 0; attempt < maxCollisionRetries; attempt++ {
		candidate := append([]byte(nil), out...)
		for _, sp := range spans {
			info := make([]byte, 0, len(real)+8)
			info = append(info, []byte(real)...)
			info = append(info, byte(sp.start), byte(sp.end))
			info = append(info, byte(attempt))
			body, err := deriveCharsetBytes(hasher, info, 0, sp.end-sp.start, sp.cs)
			if err != nil {
				return "", err
			}
			candidate = append(candidate[:sp.start], append(body, candidate[sp.end:]...)...)
		}
		masked := string(candidate)
		if masked == real {
			continue
		}
		if other, exists := existing[masked]; exists && other != real {
			continue
		}
		return masked, nil
	}
	return "", ErrMaskExhaustedRetries
}

func deriveCharsetBytes(hasher Hasher, info []byte, attempt, n int, cs []byte) ([]byte, error) {
	csLen := len(cs)
	if csLen == 0 || csLen > 256 {
		return nil, fmt.Errorf("invalid charset length %d", csLen)
	}
	maxAccepted := (256 / csLen) * csLen
	if maxAccepted == 0 {
		maxAccepted = 256
	}

	sep := append(append([]byte(nil), info...), byte(attempt))
	stream := hasher.Stream(sep)
	out := make([]byte, n)
	buf := make([]byte, 64)
	written := 0
	for written < n {
		nr, err := stream.Read(buf)
		if err != nil {
			return nil, fmt.Errorf("HKDF stream read failed: %w", err)
		}
		for i := 0; i < nr && written < n; i++ {
			if int(buf[i]) >= maxAccepted {
				continue
			}
			out[written] = cs[int(buf[i])%csLen]
			written++
		}
	}
	return out, nil
}
