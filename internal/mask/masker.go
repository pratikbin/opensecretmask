package mask

import (
	"bytes"
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"sync"

	"github.com/pratikbin/opensecretmask/internal/detect"
	"github.com/pratikbin/opensecretmask/internal/store"
)

var marshalBufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

const maxGarbleRetries = 8

// regSecret pairs a registered secret with its original value pre-converted to
// bytes. maskBytes runs per JSON string leaf, so converting each original once
// per request avoids repeating the conversion on every leaf.
type regSecret struct {
	secret store.Secret
	orig   []byte
}

// Masker rewrites secrets in request bodies to format-preserving masks and
// reverses the substitution on responses. It binds a Detector to a Store.
type Masker struct {
	store    *store.Store
	detector *detect.Detector
}

// NewMasker returns a Masker over st and det.
func NewMasker(st *store.Store, det *detect.Detector) *Masker {
	return &Masker{store: st, detector: det}
}

// MaskBody replaces every secret found in body with its mask, registering
// newly-detected secrets in the store. It returns the rewritten body and the
// secrets used — each with Original and Mask populated — which the caller
// passes to UnmaskBody / NewStreamUnmasker for the matching response.
//
// When body is JSON, each string value is masked in its decoded form and the
// document is re-marshalled. Masking the raw bytes would let a mask land
// inside a JSON escape sequence (\n, \uXXXX, ...) and corrupt it; decoding
// first keeps detection and replacement clear of escaping entirely. Non-JSON
// bodies are masked whole, byte-for-byte.
func (m *Masker) MaskBody(ctx context.Context, body []byte) ([]byte, []store.Secret, error) {
	// Fetch registered secrets once — maskBytes runs per JSON string leaf, so
	// querying inside it would issue one DB call per leaf. Pre-convert each
	// original to bytes here for the same reason.
	reg, err := m.store.RegisteredSecrets(ctx)
	if err != nil {
		return nil, nil, err
	}
	regB := make([]regSecret, 0, len(reg))
	for _, s := range reg {
		if s.Original == "" {
			continue
		}
		regB = append(regB, regSecret{secret: s, orig: []byte(s.Original)})
	}
	doc, err := decodeJSON(body)
	if err != nil {
		return m.maskBytes(ctx, body, regB) // not JSON — fall back to whole-body masking
	}
	used := make(map[int64]store.Secret)
	masked, err := m.maskJSONValue(ctx, doc, used, regB)
	if err != nil {
		return nil, nil, err
	}
	if len(used) == 0 {
		return body, nil, nil
	}
	out, err := marshalJSON(masked)
	if err != nil {
		return nil, nil, err
	}
	return out, sortedSecrets(used), nil
}

// maskBytes detects every secret in body and replaces it with its mask. It is
// the raw byte-level masker: MaskBody applies it per JSON string value, and
// falls back to it whole-body for non-JSON payloads.
func (m *Masker) maskBytes(ctx context.Context, body []byte, reg []regSecret) ([]byte, []store.Secret, error) {
	targets := make(map[string]store.Secret) // original -> secret

	for _, rs := range reg {
		if bytes.Contains(body, rs.orig) {
			targets[rs.secret.Original] = rs.secret
		}
	}

	for _, f := range m.detector.Scan(body) {
		if _, done := targets[f.Value]; done {
			continue
		}
		sec, err := m.resolve(ctx, f)
		if err != nil {
			return nil, nil, err
		}
		targets[f.Value] = sec
	}

	if len(targets) == 0 {
		return body, nil, nil
	}

	used := make([]store.Secret, 0, len(targets))
	for _, s := range targets {
		used = append(used, s)
	}
	// Replace longest originals first so a short secret that is a substring of
	// a longer one cannot corrupt the longer match.
	slices.SortFunc(used, func(a, b store.Secret) int {
		return cmp.Compare(len(b.Original), len(a.Original))
	})

	out := body
	for _, s := range used {
		out = bytes.ReplaceAll(out, []byte(s.Original), []byte(s.Mask))
		_ = m.store.TouchSecret(ctx, s.ID)
	}
	return out, used, nil
}

// maskJSONValue recursively masks every string leaf in v, recording the
// secrets used by ID. Maps and slices are rewritten in place.
func (m *Masker) maskJSONValue(ctx context.Context, v any, used map[int64]store.Secret, reg []regSecret) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			nv, err := m.maskJSONValue(ctx, child, used, reg)
			if err != nil {
				return nil, err
			}
			t[k] = nv
		}
		return t, nil
	case []any:
		for i, child := range t {
			nv, err := m.maskJSONValue(ctx, child, used, reg)
			if err != nil {
				return nil, err
			}
			t[i] = nv
		}
		return t, nil
	case string:
		if t == "" {
			return t, nil
		}
		masked, secs, err := m.maskBytes(ctx, []byte(t), reg)
		if err != nil {
			return nil, err
		}
		if len(secs) == 0 {
			return t, nil // nothing masked — skip string(masked) alloc
		}
		for _, s := range secs {
			used[s.ID] = s
		}
		return string(masked), nil
	default:
		return v, nil
	}
}

// UnmaskBody reverses MaskBody for a complete (non-streaming) response: every
// mask in secrets that appears in body is replaced with its original. secrets
// is the list returned by the MaskBody call for the same exchange.
func (m *Masker) UnmaskBody(body []byte, secrets []store.Secret) []byte {
	if len(secrets) == 0 {
		return body
	}
	ordered := slices.Clone(secrets)
	slices.SortFunc(ordered, func(a, b store.Secret) int {
		return cmp.Compare(len(b.Mask), len(a.Mask))
	})
	out := body
	for _, s := range ordered {
		// bytes.ReplaceAll copies the whole buffer even with zero matches;
		// skip masks the response never echoed back.
		mask := []byte(s.Mask)
		if len(mask) > 0 && bytes.Contains(out, mask) {
			out = bytes.ReplaceAll(out, mask, []byte(s.Original))
		}
	}
	return out
}

// Register stores value as a named, user-registered secret and returns it
// with a freshly generated mask. If value is already stored, the existing
// record is returned unchanged.
func (m *Masker) Register(ctx context.Context, name, value string) (store.Secret, error) {
	existing, err := m.store.SecretByOriginal(ctx, value)
	if err == nil {
		return *existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return store.Secret{}, err
	}
	return m.create(ctx, name, "registered", value)
}

// resolve returns the stored secret for a detector finding, creating and
// persisting a new format-preserving mask the first time a value is seen.
func (m *Masker) resolve(ctx context.Context, f detect.Finding) (store.Secret, error) {
	existing, err := m.store.SecretByOriginal(ctx, f.Value)
	if err == nil {
		return *existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return store.Secret{}, err
	}
	return m.create(ctx, f.Rule, "detected", f.Value)
}

// create generates a unique format-preserving mask for value and persists it
// as a new secret.
func (m *Masker) create(ctx context.Context, name, source, value string) (store.Secret, error) {
	mk, err := m.uniqueMask(ctx, value, m.detector.LiteralPrefixLen(value))
	if err != nil {
		return store.Secret{}, err
	}
	sec := store.Secret{
		Name:     name,
		Source:   source,
		Original: value,
		Mask:     mk,
		Shape:    shapeOf(value),
	}
	id, err := m.store.PutSecret(ctx, sec)
	if err != nil {
		return store.Secret{}, err
	}
	sec.ID = id
	return sec, nil
}

// uniqueMask garbles value into a format-preserving mask that differs from
// value and collides with no stored mask.
func (m *Masker) uniqueMask(ctx context.Context, value string, keepPrefix int) (string, error) {
	for range maxGarbleRetries {
		candidate := Garble(value, keepPrefix)
		if candidate == value {
			continue
		}
		exists, err := m.store.MaskExists(ctx, candidate)
		if err != nil {
			return "", err
		}
		if !exists {
			return candidate, nil
		}
	}
	return "", errors.New("mask: could not generate a unique mask")
}

// shapeOf returns a class summary of value: 9 for digits, a for lowercase, A
// for uppercase, structural bytes left as-is.
func shapeOf(value string) string {
	b := []byte(value)
	for i, c := range b {
		switch {
		case c >= '0' && c <= '9':
			b[i] = '9'
		case c >= 'a' && c <= 'z':
			b[i] = 'a'
		case c >= 'A' && c <= 'Z':
			b[i] = 'A'
		}
	}
	return string(b)
}

// decodeJSON decodes b as exactly one JSON value, keeping numbers as
// json.Number so a re-marshal reproduces them byte-for-byte. It errors when b
// is not JSON or carries trailing data, which routes MaskBody to the
// byte-level fallback.
func decodeJSON(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var rest any
	if err := dec.Decode(&rest); err != io.EOF {
		return nil, errors.New("mask: body is not a single JSON value")
	}
	return v, nil
}

// marshalJSON encodes v without HTML escaping and without the trailing newline
// json.Encoder appends.
func marshalJSON(v any) ([]byte, error) {
	buf := marshalBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		marshalBufPool.Put(buf)
		return nil, err
	}
	trimmed := bytes.TrimRight(buf.Bytes(), "\n")
	out := make([]byte, len(trimmed))
	copy(out, trimmed)
	marshalBufPool.Put(buf)
	return out, nil
}

// sortedSecrets returns the map's secrets ordered by ID, for deterministic
// output.
func sortedSecrets(used map[int64]store.Secret) []store.Secret {
	out := make([]store.Secret, 0, len(used))
	for _, s := range used {
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b store.Secret) int { return cmp.Compare(a.ID, b.ID) })
	return out
}
