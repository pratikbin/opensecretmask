package proxyproc

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

// shutdownTimeout bounds how long in-flight requests get to drain once
// cancellation arrives. LLM responses stream for minutes; this is the drain
// window after the client is already going away, not a request budget.
const shutdownTimeout = 10 * time.Second

// Serve runs both servers until ctx is cancelled or one of them fails, drains
// in-flight requests, then releases everything Start acquired: the daemon
// record, the listeners, and the store.
//
// Cancellation is the caller's to supply. The runtime never installs signal
// handlers — that conversion belongs at the CLI edge, where a process knows
// whether it is a foreground command or a daemon.
func (r *Runtime) Serve(ctx context.Context) error {
	g, gctx := errgroup.WithContext(ctx)

	// errgroup only cancels gctx when a member returns non-nil, or when
	// Wait itself returns — which can't happen while the drain goroutine
	// below is still blocked inside that same Wait. So the drain goroutine
	// must also wake when both servers have already exited on their own
	// (e.g. a caller-supplied ctx that is never cancelled, or a second Serve
	// on a Runtime whose servers are already shut down): stopped closes once
	// both server goroutines finish, and the drain select watches it
	// alongside gctx.Done().
	var srvWG sync.WaitGroup
	srvWG.Add(2)
	stopped := make(chan struct{})
	go func() { srvWG.Wait(); close(stopped) }()

	g.Go(func() error {
		defer srvWG.Done()
		if err := r.pxy.Serve(r.pxyLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})
	g.Go(func() error {
		defer srvWG.Done()
		if err := r.dash.Serve(r.dashLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})
	g.Go(func() error {
		select {
		case <-gctx.Done():
		case <-stopped:
			return nil // both servers already exited; nothing to drain
		}
		sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		r.logger.Info("shutting down, draining requests")
		pxyErr := r.pxy.Shutdown(sctx)
		if pxyErr != nil {
			r.logger.Error("proxy shutdown", "err", pxyErr)
		}
		dashErr := r.dash.Shutdown(sctx)
		if dashErr != nil {
			r.logger.Error("dashboard shutdown", "err", dashErr)
		}
		return errors.Join(pxyErr, dashErr)
	})
	serveErr := g.Wait()

	// Teardown mirrors Start: the record goes first so no one discovers a
	// dying daemon, then history writes drain, then the store closes. The
	// order matters — a history write landing on a closed store has nowhere
	// to report the failure. Listener closure is Shutdown's job.
	if r.cfg.Unpublish != nil {
		r.cfg.Unpublish()
	}
	r.history.Close()
	return errors.Join(serveErr, r.store.Close())
}
