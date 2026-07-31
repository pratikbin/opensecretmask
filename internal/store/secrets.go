package store

import (
	"context"
	"time"
)

// Secret is a secret value and its format-preserving mask. Original is held in
// memory only — it is never stored in plaintext.
type Secret struct {
	ID       int64
	Name     string
	Source   string // "registered" or "detected"
	Original string
	Mask     string
	Shape    string
}

// SecretMeta is a secret's metadata without the plaintext original — safe to
// list in the dashboard.
type SecretMeta struct {
	ID        int64
	Name      string
	Source    string
	Mask      string
	Shape     string
	CreatedAt time.Time
	LastUsed  time.Time
	Hits      int64
}

func nowMS() int64 { return time.Now().UnixMilli() }

// PutSecret stores sec, encrypting its Original. If the same Original already
// exists (dedup by HMAC index), the existing row ID is returned unchanged.
func (s *Store) PutSecret(ctx context.Context, sec Secret) (int64, error) {
	if s.c == nil {
		return 0, ErrLocked
	}
	idx := s.c.Index([]byte(sec.Original))
	ct, err := s.c.Encrypt([]byte(sec.Original))
	if err != nil {
		return 0, err
	}
	now := nowMS()

	// Atomic idempotent upsert. A separate SELECT-then-INSERT races: two
	// concurrent requests carrying the same brand-new secret both miss the
	// SELECT, both INSERT, and the loser fails the orig_index UNIQUE
	// constraint — which fails the whole request closed. ON CONFLICT folds the
	// duplicate into the existing row; the no-op DO UPDATE makes RETURNING
	// yield its id on the conflict path too.
	var id int64
	var storedMask string
	err = s.db.QueryRowContext(ctx,
		`INSERT INTO secrets(name, source, orig_index, orig_ct, mask, shape, created_at, last_used, hits)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, 0)
		 ON CONFLICT(orig_index) DO UPDATE SET orig_index = orig_index
		 RETURNING id, mask`,
		sec.Name, sec.Source, idx, ct, sec.Mask, sec.Shape, now, now).Scan(&id, &storedMask)
	if err != nil {
		return 0, err
	}
	s.bumpVersion(ctx)
	// Update in-memory mask set so MaskExists skips DB for subsequent garble checks.
	// Use storedMask (not sec.Mask) so ON CONFLICT paths record the existing row's mask.
	s.maskMu.Lock()
	if s.maskSet != nil {
		s.maskSet[storedMask] = struct{}{}
	}
	s.maskMu.Unlock()
	// Invalidate registered-secrets cache when a user-registered secret is added.
	if sec.Source == "registered" {
		s.regMu.Lock()
		s.regCache = nil
		s.regMu.Unlock()
	}
	return id, nil
}

// SecretByMask returns the secret whose mask equals mask, with Original
// decrypted. The error is sql.ErrNoRows when no row matches.
func (s *Store) SecretByMask(ctx context.Context, mask string) (*Secret, error) {
	if s.c == nil {
		return nil, ErrLocked
	}
	var sec Secret
	var ct []byte
	if err := s.db.QueryRowContext(ctx,
		"SELECT id, name, source, orig_ct, mask, shape FROM secrets WHERE mask = ?", mask).
		Scan(&sec.ID, &sec.Name, &sec.Source, &ct, &sec.Mask, &sec.Shape); err != nil {
		return nil, err
	}
	pt, err := s.c.Decrypt(ct)
	if err != nil {
		return nil, err
	}
	sec.Original = string(pt)
	return &sec, nil
}

// SecretByOriginal returns the secret matching original via the HMAC index.
// The error is sql.ErrNoRows when no row matches.
func (s *Store) SecretByOriginal(ctx context.Context, original string) (*Secret, error) {
	if s.c == nil {
		return nil, ErrLocked
	}
	idx := s.c.Index([]byte(original))
	var sec Secret
	if err := s.db.QueryRowContext(ctx,
		"SELECT id, name, source, mask, shape FROM secrets WHERE orig_index = ?", idx).
		Scan(&sec.ID, &sec.Name, &sec.Source, &sec.Mask, &sec.Shape); err != nil {
		return nil, err
	}
	sec.Original = original
	return &sec, nil
}

// ListSecrets returns metadata for all secrets, newest first, without
// decrypting any originals.
func (s *Store) ListSecrets(ctx context.Context) ([]SecretMeta, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, source, mask, shape, created_at, last_used, hits
		 FROM secrets ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []SecretMeta
	for rows.Next() {
		var m SecretMeta
		var created, used int64
		if err := rows.Scan(
			&m.ID, &m.Name, &m.Source, &m.Mask, &m.Shape, &created, &used, &m.Hits); err != nil {
			return nil, err
		}
		m.CreatedAt = time.UnixMilli(created)
		m.LastUsed = time.UnixMilli(used)
		out = append(out, m)
	}
	return out, rows.Err()
}

// RevealSecret decrypts and returns the plaintext original for id — used by
// the dashboard reveal-on-click.
func (s *Store) RevealSecret(ctx context.Context, id int64) (string, error) {
	if s.c == nil {
		return "", ErrLocked
	}
	var ct []byte
	if err := s.db.QueryRowContext(ctx,
		"SELECT orig_ct FROM secrets WHERE id = ?", id).Scan(&ct); err != nil {
		return "", err
	}
	pt, err := s.c.Decrypt(ct)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// TouchSecret increments the hit counter and updates last_used for id.
func (s *Store) TouchSecret(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx,
		"UPDATE secrets SET hits = hits + 1, last_used = ? WHERE id = ?", nowMS(), id)
	return err
}

// RegisteredSecrets returns every user-registered secret with Original
// decrypted — the exact-match layer used when masking request bodies.
func (s *Store) RegisteredSecrets(ctx context.Context) ([]Secret, error) {
	if s.c == nil {
		return nil, ErrLocked
	}
	dbVer, err := s.readVersion(ctx)
	if err != nil {
		return nil, err
	}
	s.regMu.RLock()
	if s.regCache != nil && s.regVersion == dbVer {
		out := make([]Secret, len(s.regCache))
		copy(out, s.regCache)
		s.regMu.RUnlock()
		return out, nil
	}
	s.regMu.RUnlock()

	s.regMu.Lock()
	defer s.regMu.Unlock()
	// Re-read version under write lock: another goroutine may have just reloaded.
	dbVer2, err := s.readVersion(ctx)
	if err != nil {
		return nil, err
	}
	if s.regCache != nil && s.regVersion == dbVer2 {
		out := make([]Secret, len(s.regCache))
		copy(out, s.regCache)
		return out, nil
	}
	loaded, err := s.loadRegisteredSecretsFromDB(ctx)
	if err != nil {
		return nil, err
	}
	s.regCache = loaded
	s.regVersion = dbVer2
	out := make([]Secret, len(loaded))
	copy(out, loaded)
	return out, nil
}

func (s *Store) loadRegisteredSecretsFromDB(ctx context.Context) ([]Secret, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, source, orig_ct, mask, shape FROM secrets WHERE source = 'registered'`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Secret
	for rows.Next() {
		var sec Secret
		var ct []byte
		if err := rows.Scan(
			&sec.ID, &sec.Name, &sec.Source, &ct, &sec.Mask, &sec.Shape); err != nil {
			return nil, err
		}
		pt, err := s.c.Decrypt(ct)
		if err != nil {
			return nil, err
		}
		sec.Original = string(pt)
		out = append(out, sec)
	}
	return out, rows.Err()
}

// MaskExists reports whether a secret with the given mask is already stored.
func (s *Store) MaskExists(ctx context.Context, mask string) (bool, error) {
	dbVer, err := s.readVersion(ctx)
	if err != nil {
		return false, err
	}
	s.maskMu.RLock()
	if s.maskSet != nil && s.maskVersion == dbVer {
		_, ok := s.maskSet[mask]
		s.maskMu.RUnlock()
		return ok, nil
	}
	s.maskMu.RUnlock()

	s.maskMu.Lock()
	defer s.maskMu.Unlock()
	dbVer2, err := s.readVersion(ctx)
	if err != nil {
		return false, err
	}
	if s.maskSet != nil && s.maskVersion == dbVer2 {
		_, ok := s.maskSet[mask]
		return ok, nil
	}
	set, err := s.loadMaskSetFromDB(ctx)
	if err != nil {
		return false, err
	}
	s.maskSet = set
	s.maskVersion = dbVer2
	_, ok := set[mask]
	return ok, nil
}

func (s *Store) loadMaskSetFromDB(ctx context.Context) (map[string]struct{}, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT mask FROM secrets")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	set := make(map[string]struct{})
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			return nil, err
		}
		set[m] = struct{}{}
	}
	return set, rows.Err()
}

// TouchSecrets increments the hit counter and updates last_used for every id in ids.
// It is a no-op when ids is empty.
func (s *Store) TouchSecrets(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	if len(ids) == 1 {
		return s.TouchSecret(ctx, ids[0])
	}
	args := make([]any, 0, len(ids)+1)
	args = append(args, nowMS())
	placeholders := make([]byte, 0, 2*len(ids)-1)
	for i, id := range ids {
		if i > 0 {
			placeholders = append(placeholders, ',')
		}
		placeholders = append(placeholders, '?')
		args = append(args, id)
	}
	_, err := s.db.ExecContext(ctx,
		// #nosec G202 -- placeholders is built only from literal '?' and ',' runes above, never from ids; values are bound via args
		"UPDATE secrets SET hits = hits + 1, last_used = ? WHERE id IN ("+string(placeholders)+")",
		args...)
	return err
}
