package store

import (
	"testing"
	"time"
)

func TestStatsAndListRequests(t *testing.T) {
	s := openTestStore(t)
	if err := s.InitCrypto(t.Context(),"pass"); err != nil {
		t.Fatalf("InitCrypto: %v", err)
	}

	if _, err := s.PutSecret(t.Context(),Secret{
		Name: "K1", Source: "registered",
		Original: "registered-secret-value", Mask: "m1", Shape: "x",
	}); err != nil {
		t.Fatalf("PutSecret registered: %v", err)
	}
	if _, err := s.PutSecret(t.Context(),Secret{
		Name: "K2", Source: "detected",
		Original: "detected-secret-value", Mask: "m2", Shape: "y",
	}); err != nil {
		t.Fatalf("PutSecret detected: %v", err)
	}

	if _, err := s.LogRequest(t.Context(),RequestRecord{
		Provider: "anthropic", Host: "api.anthropic.com",
		Method: "POST", Path: "/v1/messages", Status: 200, Masked: 2,
	}, nil); err != nil {
		t.Fatalf("LogRequest 1: %v", err)
	}
	if _, err := s.LogRequest(t.Context(),RequestRecord{
		Provider: "openai", Host: "api.openai.com",
		Method: "POST", Path: "/v1/chat/completions", Status: 200, Masked: 0,
	}, nil); err != nil {
		t.Fatalf("LogRequest 2: %v", err)
	}

	st, err := s.Stats(t.Context())
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.Secrets != 2 || st.Registered != 1 || st.Detected != 1 {
		t.Fatalf("secret stats wrong: %+v", st)
	}
	if st.Requests != 2 || st.MaskedRequests != 1 || st.TotalMasked != 2 {
		t.Fatalf("request stats wrong: %+v", st)
	}

	rows, err := s.ListRequests(t.Context(),10)
	if err != nil {
		t.Fatalf("ListRequests: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(rows))
	}
	if rows[0].Path != "/v1/chat/completions" {
		t.Fatalf("expected newest request first, got %q", rows[0].Path)
	}
}

func TestStatsEmpty(t *testing.T) {
	s := openTestStore(t)
	if err := s.InitCrypto(t.Context(),"pass"); err != nil {
		t.Fatalf("InitCrypto: %v", err)
	}
	st, err := s.Stats(t.Context())
	if err != nil {
		t.Fatalf("Stats on empty store: %v", err)
	}
	if st != (Stats{}) {
		t.Fatalf("empty store should give zero stats, got %+v", st)
	}
}

func TestGetRequestAndPurge(t *testing.T) {
	s := openTestStore(t)
	if err := s.InitCrypto(t.Context(),"pass"); err != nil {
		t.Fatalf("InitCrypto: %v", err)
	}
	secID, err := s.PutSecret(t.Context(),Secret{
		Name: "K", Source: "registered",
		Original: "real-secret-value", Mask: "MASKED01", Shape: "x",
	})
	if err != nil {
		t.Fatalf("PutSecret: %v", err)
	}

	body := []byte(`{"k":"MASKED01"}`)
	reqID, err := s.LogRequest(t.Context(),RequestRecord{
		Provider: "anthropic", Host: "api.anthropic.com",
		Method: "POST", Path: "/v1/messages", Status: 200, Masked: 1,
		ReqBody: body, RespBody: body,
	}, []int64{secID})
	if err != nil {
		t.Fatalf("LogRequest: %v", err)
	}

	d, err := s.GetRequest(t.Context(),reqID)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if string(d.ReqBody) != string(body) || string(d.RespBody) != string(body) {
		t.Fatalf("GetRequest bodies not round-tripped: %q / %q", d.ReqBody, d.RespBody)
	}
	if len(d.Secrets) != 1 || d.Secrets[0].Mask != "MASKED01" {
		t.Fatalf("GetRequest secrets wrong: %+v", d.Secrets)
	}

	// A one-day window leaves the just-logged request untouched.
	if n, err := s.PurgeRequestsOlderThan(t.Context(),24 * time.Hour); err != nil || n != 0 {
		t.Fatalf("purge fresh request: n=%d err=%v", n, err)
	}
	// A negative window puts the cutoff in the future, matching every row;
	// the delete cascades to request_secrets.
	if n, err := s.PurgeRequestsOlderThan(t.Context(),-time.Hour); err != nil || n != 1 {
		t.Fatalf("purge all: n=%d err=%v", n, err)
	}
	if _, err := s.GetRequest(t.Context(),reqID); err == nil {
		t.Fatal("GetRequest should fail after the request is purged")
	}
}


