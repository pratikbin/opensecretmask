package store

import (
	"context"
	"time"
)

// Stats is a snapshot of dashboard counters.
type Stats struct {
	Secrets        int
	Registered     int
	Detected       int
	Requests       int
	MaskedRequests int
	TotalMasked    int
}

// Stats returns aggregate counts for the dashboard overview.
func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var st Stats
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*),
		        COALESCE(SUM(source = 'registered'), 0),
		        COALESCE(SUM(source = 'detected'), 0)
		 FROM secrets`).Scan(&st.Secrets, &st.Registered, &st.Detected); err != nil {
		return st, err
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*),
		        COALESCE(SUM(masked > 0), 0),
		        COALESCE(SUM(masked), 0)
		 FROM requests`).Scan(&st.Requests, &st.MaskedRequests, &st.TotalMasked); err != nil {
		return st, err
	}
	return st, nil
}

// RequestRow is one logged request as shown in the dashboard.
type RequestRow struct {
	ID         int64
	Time       time.Time
	Provider   string
	Host       string
	Method     string
	Path       string
	Status     int
	SSE        bool
	Masked     int
	DurationMS int64
	ErrMsg     string
}

// ListRequests returns the most recent requests, newest first.
func (s *Store) ListRequests(ctx context.Context, limit int) ([]RequestRow, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, ts, provider, host, method, path, status, sse, masked, duration_ms, err
		 FROM requests ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []RequestRow
	for rows.Next() {
		var r RequestRow
		var ts int64
		var sse int
		if err := rows.Scan(&r.ID, &ts, &r.Provider, &r.Host, &r.Method, &r.Path,
			&r.Status, &sse, &r.Masked, &r.DurationMS, &r.ErrMsg); err != nil {
			return nil, err
		}
		r.Time = time.UnixMilli(ts)
		r.SSE = sse != 0
		out = append(out, r)
	}
	return out, rows.Err()
}
