package proxyproc

import (
	"context"
	"errors"
	"net/http"
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
	g.Go(func() error {
		if err := r.pxy.Serve(r.pxyLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})
	g.Go(func() error {
		if err := r.dash.Serve(r.dashLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})
	g.Go(func() error {
		<-gctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		r.logger.Info("shutting down, draining requests")
		if err := r.pxy.Shutdown(sctx); err != nil {
			r.logger.Error("proxy shutdown", "err", err)
		}
		if err := r.dash.Shutdown(sctx); err != nil {
			r.logger.Error("dashboard shutdown", "err", err)
		}
		return nil
	})
	serveErr := g.Wait()

	// Teardown mirrors Start: the record goes first so no one discovers a
	// dying daemon, then the store. Listener closure is Shutdown's job.
	if r.cfg.Unpublish != nil {
		r.cfg.Unpublish()
	}
	return errors.Join(serveErr, r.store.Close())
}
