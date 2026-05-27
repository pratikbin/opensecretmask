package store

import (
	"context"
	"fmt"
	"time"
)

// RequestRecord is one proxied request, logged for the dashboard. ReqBody and
// RespBody hold the masked bodies — what the LLM actually saw — so they carry
// no plaintext secrets.
type RequestRecord struct {
	Provider   string
	Host       string
	Method     string
	Path       string
	Status     int
	SSE        bool
	Masked     int
	DurationMS int64
	ErrMsg     string
	ReqBody    []byte
	RespBody   []byte
}

// LogRequest records a proxied request and links the secrets it touched. The
// request row and its secret links are written in one transaction: a link
// failure rolls back the request row too, so the log never holds a request
// with its secret links missing.
func (s *Store) LogRequest(ctx context.Context, r RequestRecord, secretIDs []int64) (int64, error) {
	sse := 0
	if r.SSE {
		sse = 1
	}
	// A nil slice would insert as SQL NULL; the body columns are NOT NULL.
	reqBody, respBody := r.ReqBody, r.RespBody
	if reqBody == nil {
		reqBody = []byte{}
	}
	if respBody == nil {
		respBody = []byte{}
	}
	encReq := s.encodeLoggedBody(reqBody)
	encResp := s.encodeLoggedBody(respBody)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }() // no-op once Commit succeeds

	res, err := tx.ExecContext(ctx,
		`INSERT INTO requests(ts, provider, host, method, path, status, sse, masked, duration_ms, err, req_body, resp_body, req_body_codec, resp_body_codec, req_body_raw_len, resp_body_raw_len)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		nowMS(), r.Provider, r.Host, r.Method, r.Path, r.Status, sse, r.Masked, r.DurationMS, r.ErrMsg,
		encReq.data, encResp.data, encReq.codec, encResp.codec, encReq.rawLen, encResp.rawLen)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	for _, sid := range secretIDs {
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO request_secrets(request_id, secret_id, direction) VALUES(?, ?, 'mask')`,
			id, sid); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}

// RequestDetail is a logged request with its captured masked bodies and the
// secrets swapped in it — backs the per-request debug view.
type RequestDetail struct {
	RequestRow
	ReqBody  []byte
	RespBody []byte
	Secrets  []SecretMeta
}

// GetRequest returns the full detail for one logged request: metadata, the
// captured masked request/response bodies, and the secrets it touched.
func (s *Store) GetRequest(ctx context.Context, id int64) (*RequestDetail, error) {
	var d RequestDetail
	var ts int64
	var sse int
	var rawReqBody, rawRespBody []byte
	var reqCodec, respCodec string
	var reqRawLen, respRawLen int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT id, ts, provider, host, method, path, status, sse, masked, duration_ms, err, req_body, resp_body, req_body_codec, resp_body_codec, req_body_raw_len, resp_body_raw_len
		 FROM requests WHERE id = ?`, id).
		Scan(&d.ID, &ts, &d.Provider, &d.Host, &d.Method, &d.Path,
			&d.Status, &sse, &d.Masked, &d.DurationMS, &d.ErrMsg, &rawReqBody, &rawRespBody,
			&reqCodec, &respCodec, &reqRawLen, &respRawLen); err != nil {
		return nil, err
	}
	reqBody, err := s.decodeLoggedBody(rawReqBody, reqCodec, reqRawLen)
	if err != nil {
		return nil, fmt.Errorf("store: decode request body: %w", err)
	}
	respBody, err := s.decodeLoggedBody(rawRespBody, respCodec, respRawLen)
	if err != nil {
		return nil, fmt.Errorf("store: decode response body: %w", err)
	}
	d.ReqBody = reqBody
	d.RespBody = respBody
	d.Time = time.UnixMilli(ts)
	d.SSE = sse != 0
	secs, err := s.requestSecrets(ctx, id)
	if err != nil {
		return nil, err
	}
	d.Secrets = secs
	return &d, nil
}

// requestSecrets returns the secrets linked to a request, ordered by name.
func (s *Store) requestSecrets(ctx context.Context, requestID int64) ([]SecretMeta, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT s.id, s.name, s.source, s.mask, s.shape, s.created_at, s.last_used, s.hits
		 FROM request_secrets rs
		 JOIN secrets s ON s.id = rs.secret_id
		 WHERE rs.request_id = ?
		 ORDER BY s.name`, requestID)
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

// PurgeRequestsOlderThan deletes request rows older than maxAge, cascading to
// their secret links. It returns the number of rows removed.
func (s *Store) PurgeRequestsOlderThan(ctx context.Context, maxAge time.Duration) (int64, error) {
	cutoff := time.Now().Add(-maxAge).UnixMilli()
	res, err := s.db.ExecContext(ctx, `DELETE FROM requests WHERE ts < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
