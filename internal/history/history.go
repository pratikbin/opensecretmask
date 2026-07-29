// Package history owns request-history policy: what is captured, whether a
// record is admitted, how it is persisted, and how long it is kept.
//
// Before this package, that policy was split three ways — the proxy decided
// the body cap and ran a write semaphore, the store decided the transaction
// and codec, and the dashboard decided retention as a side effect of being
// open. Changing "how much history do we keep" meant reading transport,
// persistence, and presentation code.
package history

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pratikbin/opensecretmask/internal/store"
)

const (
	// MaxBody caps the bytes persisted per captured body, keeping the request
	// log from bloating on long conversations.
	MaxBody = 256 << 10

	// DefaultRetention is how long captured requests are kept: the masked
	// bodies are debug data, not a permanent record.
	DefaultRetention = 7 * 24 * time.Hour

	// writeConcurrency bounds simultaneous history writes. History is
	// best-effort: a saturated pool drops the newest record rather than
	// applying backpressure to a live LLM request.
	writeConcurrency = 32

	// purgeInterval is how often retention is enforced while the process runs.
	purgeInterval = time.Hour
)

// Capture caps b for storage and returns a copy.
//
// Callers must invoke this synchronously at the capture point, not inside an
// async write: the proxy reads bodies into buffers that can be hundreds of
// megabytes, and cloning here is what lets that buffer be freed at once.
func Capture(b []byte) []byte {
	if len(b) > MaxBody {
		b = b[:MaxBody]
	}
	return bytes.Clone(b)
}

// Exchange is one proxied request as history sees it. Bodies hold the masked
// bytes — what the provider actually received — so they carry no plaintext
// secrets.
type Exchange struct {
	Provider  string
	Host      string
	Method    string
	Path      string
	Status    int
	SSE       bool
	Masked    int
	Duration  time.Duration
	ErrMsg    string
	ReqBody   []byte
	RespBody  []byte
	SecretIDs []int64
}

// Config configures a Recorder. A nil Store makes the recorder a silent sink,
// which is what a proxy running without history configured wants.
type Config struct {
	Store  *store.Store
	Logger *slog.Logger
	// Retention is how long records are kept. Zero disables purging entirely.
	Retention time.Duration
}

// Recorder admits, persists, and expires request history. Its methods are safe
// on a nil receiver so callers can hold an optional recorder without guards.
type Recorder struct {
	store  *store.Store
	logger *slog.Logger

	sem     chan struct{} // bounded admission
	wg      sync.WaitGroup
	dropped atomic.Int64

	done chan struct{}
	stop sync.Once
}

// NewRecorder starts the retention loop (when Retention is positive) and
// returns a recorder ready to admit records.
func NewRecorder(cfg Config) *Recorder {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	r := &Recorder{
		store:  cfg.Store,
		logger: logger,
		sem:    make(chan struct{}, writeConcurrency),
		done:   make(chan struct{}),
	}
	if cfg.Store != nil && cfg.Retention > 0 {
		r.wg.Go(func() { r.purgeLoop(cfg.Retention) })
	}
	return r
}

// Record admits an exchange for persistence. It never blocks: a full write
// pool drops the newest record and counts it, so a burst of traffic slows
// nothing on the request path. Dropped reports the running total.
func (r *Recorder) Record(ex Exchange) {
	if r == nil || r.store == nil {
		return
	}
	rec := store.RequestRecord{
		Provider:   ex.Provider,
		Host:       ex.Host,
		Method:     ex.Method,
		Path:       ex.Path,
		Status:     ex.Status,
		SSE:        ex.SSE,
		Masked:     ex.Masked,
		DurationMS: ex.Duration.Milliseconds(),
		ErrMsg:     ex.ErrMsg,
		ReqBody:    ex.ReqBody,
		RespBody:   ex.RespBody,
	}
	ids := ex.SecretIDs
	select {
	case r.sem <- struct{}{}:
		r.wg.Go(func() {
			defer func() { <-r.sem }()
			if _, err := r.store.LogRequest(context.Background(), rec, ids); err != nil {
				r.logger.Error("log request to store", "err", err)
			}
		})
	default:
		total := r.dropped.Add(1)
		r.logger.Warn("history queue full, dropping request log",
			"host", ex.Host, "path", ex.Path, "dropped_total", total)
	}
}

// Dropped is the number of records this process discarded because the write
// pool was saturated. It is in-memory and process-local: the dashboard runs
// inside the daemon and can show it, other processes cannot.
func (r *Recorder) Dropped() int64 {
	if r == nil {
		return 0
	}
	return r.dropped.Load()
}

// Close stops the retention loop and waits for in-flight writes to finish. The
// caller must invoke it before closing the store — a write landing on a closed
// store is an error the request path can no longer report. Safe to call more
// than once.
func (r *Recorder) Close() {
	if r == nil {
		return
	}
	r.stop.Do(func() { close(r.done) })
	r.wg.Wait()
}

// purgeLoop enforces retention once at startup and hourly thereafter, for as
// long as the process runs — not for as long as somebody has the dashboard
// open.
func (r *Recorder) purgeLoop(retention time.Duration) {
	r.purgeOnce(retention)
	t := time.NewTicker(purgeInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			r.purgeOnce(retention)
		case <-r.done:
			return
		}
	}
}

func (r *Recorder) purgeOnce(retention time.Duration) {
	n, err := r.store.PurgeRequestsOlderThan(context.Background(), retention)
	if err != nil {
		r.logger.Error("purge old requests", "err", err)
		return
	}
	if n > 0 {
		r.logger.Info("purged old requests", "count", n, "retention", retention.String())
	}
}
