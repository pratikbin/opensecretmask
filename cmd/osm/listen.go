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

// isShortFormLoopback recognizes legacy BSD-style short-form dotted-decimal
// loopback literals (e.g. "127.1", "127.0.1") that net.ParseIP rejects but
// the OS resolver still accepts as within 127.0.0.0/8. Purely numeric string
// parsing, no DNS involved.
func isShortFormLoopback(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) > 4 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		if _, err := strconv.Atoi(p); err != nil {
			return false
		}
	}
	first, err := strconv.Atoi(parts[0])
	return err == nil && first == 127
}
