// Package store is the encrypted SQLite persistence layer: secret<->mask
// mappings, request history, and audit events.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/pratikbin/opensecretmask/internal/crypto"

	_ "modernc.org/sqlite"
)

const verifierPlaintext = "opensecretmask-verifier-v1"

// ErrLocked is returned by operations that need crypto before Unlock succeeds.
var ErrLocked = errors.New("store: locked — call Unlock first")

// ErrWrongPassphrase is returned by Unlock when the passphrase does not match
// the one set by InitCrypto.
var ErrWrongPassphrase = errors.New("store: wrong passphrase")

// Store is the opensecretmask database handle.
type Store struct {
	db *sql.DB
	c  *crypto.Cipher

	regMu    sync.RWMutex
	regCache []Secret // nil = not loaded; invalidated on writes
	maskMu   sync.RWMutex
	maskSet  map[string]struct{} // nil = not loaded; updated on writes
}

// Open opens (creating if needed) the SQLite database at path and applies the
// schema. The returned Store is locked: call InitCrypto once on a fresh
// database, then Unlock on every subsequent open.
func Open(ctx context.Context, path string) (*Store, error) {
	dsn := "file:" + path +
		"?_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite allows one writer at a time. Capping the pool at a single
	// connection serializes all access, trading read parallelism for the
	// elimination of SQLITE_BUSY contention — fine for a local single-user tool.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(1 * time.Hour)
	db.SetConnMaxIdleTime(10 * time.Minute)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: schema: %w", err)
	}
	migrate(ctx, db)
	return &Store{db: db}, nil
}

// migrate applies best-effort column additions for databases created before a
// schema change. A duplicate-column error means the column already exists and
// is safely ignored.
func migrate(ctx context.Context, db *sql.DB) {
	for _, stmt := range []string{
		`ALTER TABLE requests ADD COLUMN req_body BLOB NOT NULL DEFAULT x''`,
		`ALTER TABLE requests ADD COLUMN resp_body BLOB NOT NULL DEFAULT x''`,
	} {
		_, _ = db.ExecContext(ctx, stmt)
	}
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) getMeta(ctx context.Context, key string) ([]byte, error) {
	var v []byte
	err := s.db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key = ?", key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return v, err
}

func (s *Store) setMeta(ctx context.Context, key string, value []byte) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO meta(key, value) VALUES(?, ?) "+
			"ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		key, value)
	return err
}

// Initialized reports whether InitCrypto has been run on this database.
func (s *Store) Initialized(ctx context.Context) (bool, error) {
	v, err := s.getMeta(ctx, "salt")
	return v != nil, err
}

// InitCrypto sets the master passphrase for a fresh database: it generates a
// salt and stores an encrypted verifier, then unlocks the store. It fails if
// the database is already initialized.
func (s *Store) InitCrypto(ctx context.Context, passphrase string) error {
	init, err := s.Initialized(ctx)
	if err != nil {
		return err
	}
	if init {
		return errors.New("store: already initialized")
	}
	salt, err := crypto.NewSalt()
	if err != nil {
		return err
	}
	c, err := crypto.NewCipher(passphrase, salt)
	if err != nil {
		return err
	}
	verifier, err := c.Encrypt([]byte(verifierPlaintext))
	if err != nil {
		return err
	}
	if err := s.setMeta(ctx, "salt", salt); err != nil {
		return err
	}
	if err := s.setMeta(ctx, "verifier", verifier); err != nil {
		return err
	}
	s.c = c
	return nil
}

// Unlock derives the cipher from passphrase and verifies it against the stored
// verifier. It returns ErrWrongPassphrase on mismatch.
func (s *Store) Unlock(ctx context.Context, passphrase string) error {
	salt, err := s.getMeta(ctx, "salt")
	if err != nil {
		return err
	}
	if salt == nil {
		return errors.New("store: not initialized — call InitCrypto first")
	}
	c, err := crypto.NewCipher(passphrase, salt)
	if err != nil {
		return err
	}
	verifier, err := s.getMeta(ctx, "verifier")
	if err != nil {
		return err
	}
	pt, err := c.Decrypt(verifier)
	if err != nil || string(pt) != verifierPlaintext {
		return ErrWrongPassphrase
	}
	s.c = c
	s.regMu.Lock()
	s.regCache = nil
	s.regMu.Unlock()
	s.maskMu.Lock()
	s.maskSet = nil
	s.maskMu.Unlock()
	return nil
}

// Unlocked reports whether the store has a usable cipher.
func (s *Store) Unlocked() bool { return s.c != nil }
