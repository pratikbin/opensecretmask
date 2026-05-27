package store_test

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/pratikbin/opensecretmask/internal/store"
)

// openTestStorePath returns an opened store and the temp DB file path so tests
// can also reach the raw SQLite row when they need to inspect storage-level
// details (codec column, on-disk BLOB size, corruption injection).
func openTestStorePath(t *testing.T) (*store.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(t.Context(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

// logCompressibleRequest writes one request row using body as BOTH req_body
// and resp_body and returns the row id.
func logCompressibleRequest(t *testing.T, s *store.Store, body []byte) int64 {
	t.Helper()
	if err := s.InitCrypto(t.Context(), "pass"); err != nil {
		t.Fatalf("InitCrypto: %v", err)
	}
	id, err := s.LogRequest(t.Context(), store.RequestRecord{
		Provider: "test", Host: "example.test",
		Method: "POST", Path: "/v1/echo", Status: 200,
		ReqBody: body, RespBody: body,
	}, nil)
	if err != nil {
		t.Fatalf("LogRequest: %v", err)
	}
	return id
}

// reopenStore closes the existing store, reopens it at the same path, and
// unlocks with the test passphrase used by logCompressibleRequest.
func reopenStore(t *testing.T, s *store.Store, path string) *store.Store {
	t.Helper()
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	s2, err := store.Open(t.Context(), path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })
	if err := s2.Unlock(t.Context(), "pass"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	return s2
}

// rawRow reads the codec-related columns of a single requests row directly via
// database/sql so the test can verify what landed on disk.
type rawRow struct {
	reqBody    []byte
	respBody   []byte
	reqCodec   string
	respCodec  string
	reqRawLen  int64
	respRawLen int64
}

func readRawRow(t *testing.T, path string, id int64) rawRow {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	var r rawRow
	err = db.QueryRowContext(t.Context(),
		`SELECT req_body, resp_body, req_body_codec, resp_body_codec, req_body_raw_len, resp_body_raw_len
		 FROM requests WHERE id = ?`, id).
		Scan(&r.reqBody, &r.respBody, &r.reqCodec, &r.respCodec, &r.reqRawLen, &r.respRawLen)
	if err != nil {
		t.Fatalf("scan raw row: %v", err)
	}
	return r
}

// execRaw runs one statement against the SQLite file directly and asserts
// exactly one row was affected.
func execRaw(t *testing.T, path, query string, args ...any) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	res, err := db.ExecContext(t.Context(), query, args...)
	if err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		t.Fatalf("RowsAffected: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 row affected, got %d", n)
	}
}

func TestLogRequestCompressesLargeBodies(t *testing.T) {
	s, path := openTestStorePath(t)
	// ~2.8 KiB of a repeating token: well above the 1 KiB threshold and
	// extremely compressible by zstd.
	body := bytes.Repeat([]byte("payload-token "), 200)
	if len(body) <= 1024 {
		t.Fatalf("test body must exceed compression threshold, got %d bytes", len(body))
	}

	id := logCompressibleRequest(t, s, body)

	row := readRawRow(t, path, id)
	if row.reqCodec != "zstd" {
		t.Fatalf("req_body_codec = %q, want %q", row.reqCodec, "zstd")
	}
	if row.respCodec != "zstd" {
		t.Fatalf("resp_body_codec = %q, want %q", row.respCodec, "zstd")
	}
	if int64(len(body)) != row.reqRawLen {
		t.Fatalf("req_body_raw_len = %d, want %d", row.reqRawLen, len(body))
	}
	if int64(len(body)) != row.respRawLen {
		t.Fatalf("resp_body_raw_len = %d, want %d", row.respRawLen, len(body))
	}
	if len(row.reqBody) >= len(body) {
		t.Fatalf("stored req_body (%d bytes) not smaller than raw body (%d bytes)", len(row.reqBody), len(body))
	}
	if len(row.respBody) >= len(body) {
		t.Fatalf("stored resp_body (%d bytes) not smaller than raw body (%d bytes)", len(row.respBody), len(body))
	}

	s2 := reopenStore(t, s, path)
	d, err := s2.GetRequest(t.Context(), id)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if !bytes.Equal(d.ReqBody, body) {
		t.Fatalf("ReqBody round-trip mismatch: got %d bytes, want %d", len(d.ReqBody), len(body))
	}
	if !bytes.Equal(d.RespBody, body) {
		t.Fatalf("RespBody round-trip mismatch: got %d bytes, want %d", len(d.RespBody), len(body))
	}
}

func TestLogRequestLeavesSmallBodiesUncompressed(t *testing.T) {
	s, path := openTestStorePath(t)
	body := []byte("hi")

	id := logCompressibleRequest(t, s, body)

	row := readRawRow(t, path, id)
	if row.reqCodec != "" {
		t.Fatalf("req_body_codec = %q, want empty for small body", row.reqCodec)
	}
	if row.respCodec != "" {
		t.Fatalf("resp_body_codec = %q, want empty for small body", row.respCodec)
	}
	if !bytes.Equal(row.reqBody, body) {
		t.Fatalf("stored req_body = %q, want %q (uncompressed identity)", row.reqBody, body)
	}
	if !bytes.Equal(row.respBody, body) {
		t.Fatalf("stored resp_body = %q, want %q (uncompressed identity)", row.respBody, body)
	}
	if row.reqRawLen != int64(len(body)) || row.respRawLen != int64(len(body)) {
		t.Fatalf("raw_len columns wrong: req=%d resp=%d want %d", row.reqRawLen, row.respRawLen, len(body))
	}

	s2 := reopenStore(t, s, path)
	d, err := s2.GetRequest(t.Context(), id)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if !bytes.Equal(d.ReqBody, body) || !bytes.Equal(d.RespBody, body) {
		t.Fatalf("uncompressed round-trip mismatch: req=%q resp=%q", d.ReqBody, d.RespBody)
	}
}

func TestGetRequestRejectsCorruptCompressedBody(t *testing.T) {
	s, path := openTestStorePath(t)
	body := bytes.Repeat([]byte("compress-me "), 200)
	id := logCompressibleRequest(t, s, body)

	// Sanity-check the row was actually written with zstd before corrupting.
	row := readRawRow(t, path, id)
	if row.reqCodec != "zstd" {
		t.Fatalf("setup: req_body_codec = %q, want zstd", row.reqCodec)
	}

	// Replace req_body with random garbage of similar length while leaving
	// the codec column at "zstd" so decode is forced to run on bad data.
	garbage := make([]byte, len(row.reqBody))
	if _, err := rand.Read(garbage); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	// Close the store so the raw UPDATE doesn't fight SQLite locks.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	execRaw(t, path, `UPDATE requests SET req_body = ? WHERE id = ?`, garbage, id)

	s2, err := store.Open(t.Context(), path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })
	if err := s2.Unlock(t.Context(), "pass"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	if _, err := s2.GetRequest(t.Context(), id); err == nil {
		t.Fatal("GetRequest should fail on corrupt zstd body")
	} else if !strings.Contains(err.Error(), "decode") {
		// Be lenient on exact wording but require the error path to be
		// the decoder, not a generic SQL failure.
		t.Fatalf("expected decode error, got %v", err)
	}
}

func TestGetRequestRejectsUnknownBodyCodec(t *testing.T) {
	s, path := openTestStorePath(t)
	body := []byte("hi")
	id := logCompressibleRequest(t, s, body)

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	execRaw(t, path, `UPDATE requests SET req_body_codec = 'lz4' WHERE id = ?`, id)

	s2, err := store.Open(t.Context(), path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })
	if err := s2.Unlock(t.Context(), "pass"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	_, err = s2.GetRequest(t.Context(), id)
	if err == nil {
		t.Fatal("GetRequest should fail on unknown codec")
	}
	if !strings.Contains(err.Error(), "lz4") && !strings.Contains(err.Error(), "unknown codec") {
		t.Fatalf("expected error to mention codec, got %v", err)
	}
}
