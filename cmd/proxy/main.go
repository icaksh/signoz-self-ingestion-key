package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sismedika/otlp-proxy/internal/admin"
	"github.com/sismedika/otlp-proxy/internal/auth"
	"github.com/sismedika/otlp-proxy/internal/config"
	"github.com/sismedika/otlp-proxy/internal/proxy"
	"github.com/sismedika/otlp-proxy/internal/ratelimit"
	"github.com/sismedika/otlp-proxy/internal/store"
	"github.com/sismedika/otlp-proxy/internal/syslog"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()

	lim := ratelimit.NewLimiter(st)
	lim.Start()
	defer lim.Stop()

	gateway := auth.NewGateway(st)

	proxyHandler, err := proxy.NewHandler(cfg.SigNozEndpoint, cfg.SigNozIngestKey, st, cfg.MaxBodyBytes, lim, gateway)
	if err != nil {
		log.Fatalf("proxy: %v", err)
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

	adminServer := admin.NewServer(st, cfg.AdminListenAddr, cfg.SessionSigningKey, cfg.AdminCookieSecure)
	adminServer.ReadHeaderTimeout = 5 * time.Second
	adminServer.ReadTimeout = 30 * time.Second
	adminServer.WriteTimeout = 30 * time.Second
	adminServer.IdleTimeout = 120 * time.Second
	adminServer.MaxHeaderBytes = 1 << 16

	// Syslog-over-TLS (mTLS) — optional
	syslogCtx, syslogCancel := context.WithCancel(context.Background())
	defer syslogCancel()
	if cfg.SyslogEnabled {
		syslogSrv, err := syslog.NewServer(syslog.Config{
			Addr:            cfg.SyslogListenAddr,
			ServerCertFile:  cfg.SyslogServerCertFile,
			ServerKeyFile:   cfg.SyslogServerKeyFile,
			ClientCAFile:    cfg.SyslogClientCAFile,
			MaxFrameBytes:   cfg.SyslogMaxFrameBytes,
			MaxConnections:  cfg.SyslogMaxConnections,
			ConnIdleTimeout: cfg.SyslogConnIdleTimeout,
			CollectorAddr:   cfg.SyslogCollectorAddr,
		}, st, gateway, lim)
		if err != nil {
			log.Fatalf("syslog: %v", err)
		}
		go func() {
			if err := syslogSrv.ListenAndServe(syslogCtx); err != nil {
				log.Printf("[syslog] %v", err)
			}
		}()
	}

	// Run cleanup at startup, then every 24h
	if err := st.CleanupOldLogs(context.Background(), cfg.UsageRetentionDays); err != nil {
		log.Printf("[cleanup] startup error: %v", err)
	} else {
		log.Printf("[cleanup] purged logs older than %d days", cfg.UsageRetentionDays)
	}
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			if err := st.CleanupOldLogs(context.Background(), cfg.UsageRetentionDays); err != nil {
				log.Printf("[cleanup] error: %v", err)
			} else {
				log.Printf("[cleanup] purged logs older than %d days", cfg.UsageRetentionDays)
			}
		}
	}()

	go func() {
		log.Printf("[proxy] listening on :%s -> %s", cfg.ProxyPort, cfg.SigNozEndpoint)
		if err := proxyServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[proxy] %v", err)
		}
	}()

	go func() {
		log.Printf("[admin] listening on %s", cfg.AdminListenAddr)
		if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[admin] %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("shutting down...")

	syslogCancel() // stop accepting syslog connections

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	proxyServer.Shutdown(ctx)
	adminServer.Shutdown(ctx)
	log.Println("stopped.")
}
