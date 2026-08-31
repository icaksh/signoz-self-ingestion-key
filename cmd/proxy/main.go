// Command proxy is the OTLP tenant-authenticating proxy + admin dashboard.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/sismedika/otlp-proxy/internal/auth"
	"github.com/sismedika/otlp-proxy/internal/config"
	"github.com/sismedika/otlp-proxy/internal/ingest"
	"github.com/sismedika/otlp-proxy/internal/pki"
	"github.com/sismedika/otlp-proxy/internal/ratelimit"
	"github.com/sismedika/otlp-proxy/internal/store"
	"github.com/sismedika/otlp-proxy/internal/syslog"
	"github.com/sismedika/otlp-proxy/internal/web"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()

	lim := ratelimit.NewLimiter(st)
	lim.Start()
	defer lim.Stop()

	gateway := auth.NewGateway(st)

	proxyHandler, err := ingest.NewHandler(cfg.SigNozEndpoint, cfg.SigNozIngestKey, st, cfg.MaxBodyBytes, lim, gateway)
	if err != nil {
		return err
	}

	proxyServer := &http.Server{
		Addr:              ":" + cfg.ProxyPort,
		Handler:           proxyHandler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	// Optional step-ca certificate lifecycle.
	var caClient *pki.Client
	var dl *pki.DownloadManager
	certLifetime := 2160 * time.Hour
	if cfg.CAEnabled {
		provKey, err := readProvisionerKey(cfg)
		if err != nil {
			return err
		}
		rootCert, err := os.ReadFile(cfg.CARootCertFile)
		if err != nil {
			return err
		}
		certLifetime, err = time.ParseDuration(cfg.CACertLifetime)
		if err != nil {
			return err
		}
		caClient, err = pki.NewClient(pki.ClientConfig{
			Endpoint:        cfg.CAEndpoint,
			ProvisionerName: cfg.CAProvisionerName,
			ProvisionerKey:  provKey,
			RootCert:        rootCert,
			Lifetime:        certLifetime,
		})
		if err != nil {
			return err
		}
		dl = pki.NewDownloadManager()
	}

	adminServer := web.New(web.Config{
		Store:             st,
		Addr:              cfg.AdminListenAddr,
		SigningKey:        cfg.SessionSigningKey,
		CookieSecure:      cfg.AdminCookieSecure,
		TrustProxyHeaders: cfg.TrustProxyHeaders,
		CAClient:          caClient,
		DownloadManager:   dl,
		CAExternalHost:    cfg.CAExternalHostname,
		CASyslogPort:      cfg.CASyslogRelayPort,
		CertLifetime:      certLifetime,
		Limiter:           lim,
	})
	adminServer.ReadHeaderTimeout = 5 * time.Second
	adminServer.ReadTimeout = 30 * time.Second
	adminServer.WriteTimeout = 30 * time.Second
	adminServer.IdleTimeout = 120 * time.Second
	adminServer.MaxHeaderBytes = 1 << 16

	// Root context owns every goroutine; cancelling stops all listeners.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	// Run startup retention cleanup (now on usage_counters).
	if err := st.CleanupOldCounters(ctx, cfg.UsageRetentionDays); err != nil {
		log.Printf("[cleanup] startup error: %v", err)
	} else {
		log.Printf("[cleanup] purged usage older than %d days", cfg.UsageRetentionDays)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := st.CleanupOldCounters(ctx, cfg.UsageRetentionDays); err != nil {
					log.Printf("[cleanup] error: %v", err)
				}
			}
		}
	}()

	// Proxy server.
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Printf("[proxy] listening on :%s -> %s", cfg.ProxyPort, cfg.SigNozEndpoint)
		if err := proxyServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[proxy] %v", err)
		}
	}()

	// Admin server.
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Printf("[admin] listening on %s", cfg.AdminListenAddr)
		if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[admin] %v", err)
		}
	}()

	// Syslog mTLS server (optional).
	if cfg.SyslogEnabled {
		syslogSrv, err := syslog.NewServer(syslog.Config{
			Addr:              cfg.SyslogListenAddr,
			ServerCertFile:    cfg.SyslogServerCertFile,
			ServerKeyFile:     cfg.SyslogServerKeyFile,
			ClientCAFile:      cfg.SyslogClientCAFile,
			MaxFrameBytes:     cfg.SyslogMaxFrameBytes,
			MaxConnections:    cfg.SyslogMaxConnections,
			MaxConnsPerTenant: cfg.SyslogMaxConnsPerTenant,
			ConnIdleTimeout:   cfg.SyslogConnIdleTimeout,
			CollectorAddr:     cfg.SyslogCollectorAddr,
		}, st, gateway, lim)
		if err != nil {
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := syslogSrv.ListenAndServe(ctx); err != nil {
				log.Printf("[syslog] %v", err)
			}
		}()
	}

	// CA renewal mTLS server (optional).
	if cfg.CAEnabled {
		renewalSrv, err := pki.NewRenewalServer(pki.RenewalConfig{
			ListenAddr:     cfg.CARenewalListenAddr,
			ClientCAFile:   cfg.SyslogClientCAFile,
			ServerCertFile: cfg.SyslogServerCertFile,
			ServerKeyFile:  cfg.SyslogServerKeyFile,
		}, st, caClient)
		if err != nil {
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Printf("[ca] renewal listener on %s (mTLS)", cfg.CARenewalListenAddr)
			if err := renewalSrv.ListenAndServe(ctx); err != nil {
				log.Printf("[ca] renewal: %v", err)
			}
		}()
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("shutting down...")
	cancel() // stop listeners + background loops

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	_ = proxyServer.Shutdown(shutdownCtx)
	_ = adminServer.Shutdown(shutdownCtx)

	// Join all goroutines (usage writer flush happens on st.Close via defer).
	wg.Wait()
	if dl != nil {
		dl.Stop()
	}
	log.Println("stopped.")
	return nil
}

func readProvisionerKey(cfg *config.Config) ([]byte, error) {
	if cfg.CAProvisionerKey != "" {
		return []byte(cfg.CAProvisionerKey), nil
	}
	return os.ReadFile(cfg.CAProvisionerKeyFile)
}
