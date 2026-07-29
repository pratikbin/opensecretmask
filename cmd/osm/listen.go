package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// validateListenAddr rejects listen addresses that would bind a non-loopback
// interface unless the operator passed --allow-external-bind. Both listeners
// are unauthenticated: the proxy answers CONNECT for arbitrary hosts and the
// dashboard reveal routes return plaintext originals, so an accidental public
// bind is a credential-exposure incident.
//
// Hostname policy: no DNS resolution. "localhost" and literal loopback IPs
// (127.0.0.0/8, ::1) pass; any other hostname is rejected with a hint to use
// a literal IP, so the check never depends on resolver state.
func validateListenAddr(addr string, allowExternal bool) error {
	if allowExternal {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		if host == "" {
			return fmt.Errorf("listen address %q binds every interface; pass --allow-external-bind to override", addr)
		}
		if isShortFormLoopback(host) {
			return nil
		}
		return fmt.Errorf("listen address %q uses an unresolved hostname; use a literal loopback IP or pass --allow-external-bind", addr)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("listen address %q is not loopback; pass --allow-external-bind to override", addr)
	}
	return nil
}

// isShortFormLoopback decodes legacy BSD-style short-form dotted-decimal
// address literals (e.g. "127.1" decodes to 127.0.0.1, "127.0.1" decodes to
// 127.0.0.1) that net.ParseIP rejects but net.Dial's literal-address parser
// still accepts, per classic inet_aton rules: for N dot-separated parts
// (2 <= N <= 4), the first N-1 parts are single octets (0-255) and the last
// part fills the remaining (5-N)*8 bits. The bare single-part form is
// rejected outright — it decodes as one 32-bit value, not an octet, so it
// cannot reliably be judged loopback from its leading digits. Any part that
// doesn't decode within its required width is rejected too, so a string
// Go's dialer would otherwise send to a real DNS lookup is never waved
// through as loopback. Loopback membership is decided on the decoded first
// octet, not on the raw leading token.
func isShortFormLoopback(host string) bool {
	parts := strings.Split(host, ".")
	n := len(parts)
	if n < 2 || n > 4 {
		return false
	}
	vals := make([]uint64, n)
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return false
		}
		vals[i] = v
	}
	// All but the last part are single octets.
	for _, v := range vals[:n-1] {
		if v > 255 {
			return false
		}
	}
	// The last part absorbs the remaining bits: 24 for the 2-part form,
	// 16 for 3-part, 8 for 4-part.
	lastBits := uint(8 * (5 - n))
	if vals[n-1] >= 1<<lastBits {
		return false
	}
	// The first part is always a single decoded octet regardless of N,
	// since only the trailing part packs multiple octets.
	return vals[0] == 127
}
