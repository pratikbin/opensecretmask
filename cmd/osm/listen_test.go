package main

import (
	"strings"
	"testing"
)

func TestValidateListenAddr(t *testing.T) {
	ok := []string{
		"127.0.0.1:8787",
		"127.1:8787", // short-form loopback literal
		"[::1]:8787",
		"localhost:8787",
	}
	for _, addr := range ok {
		if err := validateListenAddr(addr, false); err != nil {
			t.Errorf("validateListenAddr(%q) = %v, want nil", addr, err)
		}
	}

	cases := []struct {
		addr    string
		wantSub string // substring the error must contain
	}{
		{":8787", "every interface"},
		{"0.0.0.0:8787", "not loopback"},
		{"[::]:8787", "not loopback"},
		{"192.168.1.5:9000", "not loopback"},
		{"8.8.8.8:53", "not loopback"},
		{"example.com:8787", "unresolved hostname"},
		{"garbage", "invalid listen address"},
	}
	for _, tc := range cases {
		err := validateListenAddr(tc.addr, false)
		if err == nil {
			t.Errorf("validateListenAddr(%q) = nil, want error containing %q", tc.addr, tc.wantSub)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("validateListenAddr(%q) = %q, want substring %q", tc.addr, err, tc.wantSub)
		}
		// The escape hatch must approve everything the guard rejected.
		if err := validateListenAddr(tc.addr, true); err != nil {
			t.Errorf("validateListenAddr(%q, allowExternal=true) = %v, want nil", tc.addr, err)
		}
	}
}
