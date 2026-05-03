package detector

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/pratikbin/opensecretmask/internal/core/transformer"
)

var (
	ErrScanCapExceeded   = errors.New("opensecretmask: scan cap exceeded")
	ErrContainerOverflow = errors.New("opensecretmask: container exceeded max_container_bytes")
	ErrUnclosedContainer = errors.New("opensecretmask: EOF inside open container; missing EndMarker")
)

// MaskFunc returns the masked replacement for a single secret value found by a rule.
// Scanner calls this for each Finding and substitutes value→mask in the output.
type MaskFunc func(value string, ruleID string) (string, error)

type Scanner struct {
	det            *Detector
	rules          []transformer.Rule
	overlap        int
	maxScan        int
	maxContainer   int
	mask           MaskFunc
	containerRules []*transformer.Rule
	onScanCap      string // "truncate" | "deny"
}

// NewScanner builds a streaming scanner. overlap is computed from rules' MaxLen
// (min 4096) so a secret straddling chunk boundary is still wholly visible to
// the detector once the next chunk arrives.
func NewScanner(det *Detector, rules []transformer.Rule, maxScan, maxContainer int, mask MaskFunc) *Scanner {
	overlap := 4096
	for _, r := range rules {
		if r.MaxLen > overlap {
			overlap = r.MaxLen
		}
	}
	var crs []*transformer.Rule
	for i := range rules {
		if rules[i].BeginMarker != "" && rules[i].EndMarker != "" {
			crs = append(crs, &rules[i])
		}
	}
	return &Scanner{
		det: det, rules: rules, overlap: overlap,
		maxScan: maxScan, maxContainer: maxContainer,
		mask: mask, containerRules: crs, onScanCap: "truncate",
	}
}

// SetOnScanCap configures cap behavior: "truncate" (default) or "deny".
func (s *Scanner) SetOnScanCap(mode string) { s.onScanCap = mode }

// Stream reads from r, masks secrets, writes to w.
//
// Two paths:
//   - Path A: a container is currently open — buffer chunks until EndMarker found
//     or maxContainer/EOF triggers fail-closed.
//   - Path B: no container open — append to scanBuf, watch for any rule's
//     BeginMarker; otherwise flush all but the trailing overlap window.
func (s *Scanner) Stream(r io.Reader, w io.Writer) error {
	scanBuf := bytes.Buffer{}
	var containerBuf []byte
	var containerRule *transformer.Rule
	scanned := 0
	chunkSize := 65536
	chunk := make([]byte, chunkSize)

	for {
		n, rerr := r.Read(chunk)
		eof := errors.Is(rerr, io.EOF)
		if rerr != nil && !eof {
			return fmt.Errorf("scanner read: %w", rerr)
		}

		// Scan-cap check before accepting these bytes.
		if scanned+n > s.maxScan {
			if s.onScanCap == "deny" {
				return ErrScanCapExceeded
			}
			// truncate: container open at cap is fail-closed (we'd otherwise drop body)
			if containerRule != nil {
				return ErrScanCapExceeded
			}
			if scanBuf.Len() > 0 {
				if err := s.flushScan(scanBuf.Bytes(), w); err != nil {
					return err
				}
				scanBuf.Reset()
			}
			withheld := n + s.drainCount(r)
			notice := fmt.Sprintf("[opensecretmask: scan-cap exceeded — %d bytes withheld]", withheld)
			if _, err := w.Write([]byte(notice)); err != nil {
				return err
			}
			return nil
		}
		scanned += n

		// Path A: container open — buffer until EndMarker.
		if containerBuf != nil {
			containerBuf = append(containerBuf, chunk[:n]...)
			if len(containerBuf) > s.maxContainer {
				return ErrContainerOverflow
			}
			endIdx := bytes.Index(containerBuf, []byte(containerRule.EndMarker))
			if endIdx >= 0 {
				closeAt := endIdx + len(containerRule.EndMarker)
				masked, err := s.applyContainerMask(containerBuf[:closeAt], containerRule)
				if err != nil {
					return err
				}
				if _, err := w.Write(masked); err != nil {
					return err
				}
				tail := append([]byte(nil), containerBuf[closeAt:]...)
				containerBuf = nil
				containerRule = nil
				scanBuf.Write(tail)
			} else if eof {
				return ErrUnclosedContainer
			}
			if eof {
				// container closed exactly at EOF; flush any tail we promoted to scanBuf.
				if scanBuf.Len() > 0 {
					if err := s.flushScan(scanBuf.Bytes(), w); err != nil {
						return err
					}
					scanBuf.Reset()
				}
				return nil
			}
			continue
		}

		// Path B: no container open.
		scanBuf.Write(chunk[:n])
		for _, cr := range s.containerRules {
			idx := bytes.Index(scanBuf.Bytes(), []byte(cr.BeginMarker))
			if idx >= 0 {
				if err := s.flushScan(scanBuf.Bytes()[:idx], w); err != nil {
					return err
				}
				containerBuf = append([]byte(nil), scanBuf.Bytes()[idx:]...)
				containerRule = cr
				scanBuf.Reset()
				break
			}
		}

		if containerBuf == nil {
			if !eof {
				if scanBuf.Len() > s.overlap {
					scanLimit := scanBuf.Len() - s.overlap
					if err := s.flushScan(scanBuf.Bytes()[:scanLimit], w); err != nil {
						return err
					}
					rem := append([]byte(nil), scanBuf.Bytes()[scanLimit:]...)
					scanBuf.Reset()
					scanBuf.Write(rem)
				}
			} else {
				if err := s.flushScan(scanBuf.Bytes(), w); err != nil {
					return err
				}
				scanBuf.Reset()
			}
		}
		if eof {
			return nil
		}
	}
}

// drainCount counts remaining bytes from r without storing them.
func (s *Scanner) drainCount(r io.Reader) int {
	buf := make([]byte, 4096)
	total := 0
	for {
		n, err := r.Read(buf)
		total += n
		if err != nil {
			return total
		}
	}
}

// flushScan: detect findings in b, replace each with mask(value, ruleID), write result.
func (s *Scanner) flushScan(b []byte, w io.Writer) error {
	if len(b) == 0 {
		return nil
	}
	hits := s.det.Detect(string(b))
	if len(hits) == 0 {
		_, err := w.Write(b)
		return err
	}
	out := bytes.Buffer{}
	last := 0
	for _, h := range hits {
		if h.Start < last {
			continue
		}
		out.Write(b[last:h.Start])
		masked, err := s.mask(h.Value, h.Rule)
		if err != nil {
			return fmt.Errorf("mask %s: %w", h.Rule, err)
		}
		out.WriteString(masked)
		last = h.End
	}
	out.Write(b[last:])
	_, err := w.Write(out.Bytes())
	return err
}

// applyContainerMask masks the entire container body in one shot.
// Detect will match the container rule on the full container.
func (s *Scanner) applyContainerMask(b []byte, rule *transformer.Rule) ([]byte, error) {
	hits := s.det.Detect(string(b))
	if len(hits) == 0 {
		return b, nil
	}
	out := bytes.Buffer{}
	last := 0
	for _, h := range hits {
		if h.Start < last {
			continue
		}
		out.Write(b[last:h.Start])
		masked, err := s.mask(h.Value, h.Rule)
		if err != nil {
			return nil, fmt.Errorf("mask container %s: %w", h.Rule, err)
		}
		out.WriteString(masked)
		last = h.End
	}
	out.Write(b[last:])
	return out.Bytes(), nil
}
