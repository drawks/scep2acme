package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	scepserver "github.com/micromdm/scep/server"
	"go.bog.dev/errpool"
)

// Server manages the HTTP server and graceful shutdown
type Server struct {
	addr   string
	logger log.Logger
}

// New creates a new server
func New(addr string, logger log.Logger) *Server {
	return &Server{
		addr:   addr,
		logger: logger,
	}
}

// Run starts the HTTP server with graceful shutdown
func (s *Server) Run(svc scepserver.Service) error {
	lginfo := level.Info(s.logger)

	// Create HTTP handler
	var h http.Handler
	{
		e := scepserver.MakeServerEndpoints(svc)
		e.GetEndpoint = scepserver.EndpointLoggingMiddleware(lginfo)(e.GetEndpoint)
		e.PostEndpoint = scepserver.EndpointLoggingMiddleware(lginfo)(e.PostEndpoint)
		h = scepserver.MakeHTTPHandler(e, svc, log.With(lginfo, "component", "http"))
	}

	pool := errpool.Unbounded(context.Background())

	server := http.Server{
		Addr:              s.addr,
		Handler:           h,
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Start HTTP server
	pool.Go(func(ctx context.Context) error {
		return server.ListenAndServe()
	})

	// Handle graceful shutdown
	pool.Go(func(ctx context.Context) error {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	})

	// Handle termination signals
	pool.Go(func(ctx context.Context) error {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGTERM)
		return fmt.Errorf("%v", <-c)
	})

	if err := lginfo.Log("terminated", pool.Wait()); err != nil {
		// Log error is typically not critical for application termination
		fmt.Fprintf(os.Stderr, "failed to log termination: %v\n", err)
	}

	return nil
}
