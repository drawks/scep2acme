package main

import (
	"fmt"
	"os"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	scepserver "github.com/micromdm/scep/server"

	"go.bog.dev/scep2acme/internal/acme"
	"go.bog.dev/scep2acme/internal/config"
	"go.bog.dev/scep2acme/internal/scep"
	"go.bog.dev/scep2acme/internal/server"
	"go.bog.dev/scep2acme/internal/whitelist"
)

func main() {
	cfg := config.ParseFlags()
	cfg.Validate()

	// Setup ACME client
	acmeClient, err := acme.NewClient(cfg.ACMEEmail, cfg.ACMEKeyPath, cfg.ACMEURL, cfg.DNSProvider)
	if err != nil {
		panic(err)
	}

	// Setup logger
	var logger log.Logger
	{
		logger = log.NewLogfmtLogger(os.Stderr)
		if !cfg.Debug {
			logger = level.NewFilter(logger, level.AllowInfo())
		}
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		logger = log.With(logger, "caller", log.DefaultCaller)
	}

	// Setup CSR verifier
	verifier, err := whitelist.NewCSRPasswordVerifier(cfg.WhitelistPath)
	if err != nil {
		panic(fmt.Errorf("loading whitelist: %w", err))
	}

	// Setup SCEP service
	depot := scep.NewDepot(cfg.CertPath, cfg.CertKeyPath)
	var svc scepserver.Service
	{
		svcOptions := []scepserver.ServiceOption{
			scepserver.WithLogger(logger),
			scepserver.WithCSRVerifier(verifier),
			scepserver.WithCertificateSource(acmeClient.CertificateSource()),
		}
		svc, err = scepserver.NewService(depot, svcOptions...)
		if err != nil {
			panic(err)
		}
		svc = scep.ServiceWithoutRenewal{Service: svc}
		svc = scepserver.NewLoggingService(log.With(level.Info(logger), "component", "scep_service"), svc)
	}

	// Start server
	srv := server.New(cfg.ListenPort, logger)
	if err := srv.Run(svc); err != nil {
		panic(err)
	}
}
