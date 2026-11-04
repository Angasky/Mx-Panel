package main

import (
	"context"
	"flag"
	"github.com/Angasky/dingzhi-ban/internal/web"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var releaseVersion = "dev"

func main() {
	listen := flag.String("listen", "127.0.0.1:62578", "listen address; development port differs from Python")
	root := flag.String("root", "/opt/mxioc-rule-manager", "application data directory")
	auth := flag.String("auth", "/etc/mxioc-rule-manager.auth.json", "existing administrator credential file")
	proxy := flag.Bool("trust-loopback-proxy", false, "trust HTTPS forwarding only from loopback reverse proxy")
	local := flag.Bool("local-development", false, "allow loopback HTTP for isolated development only")
	check := flag.Bool("check-data", false, "validate existing credentials and every subscription without starting services")
	adminHTML := flag.String("admin-html", "", "optional release-specific administrator HTML path")
	bootstrapUser := flag.String("bootstrap-user", "", "initialize a fresh data directory and account using a password read from stdin")
	flag.Parse()
	if *bootstrapUser != "" {
		if *check {
			log.Fatal("--bootstrap-user and --check-data are mutually exclusive")
		}
		if err := bootstrap(*root, *auth, *bootstrapUser, os.Stdin); err != nil {
			log.Fatal("initialization failed: ", err)
		}
		return
	}
	handler, err := web.New(web.Options{Root: *root, AuthFile: *auth, AdminHTML: *adminHTML, Version: releaseVersion, TrustLoopbackProxy: *proxy, LocalDevelopment: *local})
	if err != nil {
		log.Fatal("startup validation failed: ", err)
	}
	if *check {
		if err = handler.CheckData(); err != nil {
			log.Fatal("data validation failed: ", err)
		}
		log.Print("existing credentials and subscription data validated; no service started")
		return
	}
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 3 * time.Minute, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err = handler.RunBackground(ctx); err != nil {
		log.Fatal("background accounting startup failed: ", err)
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.Print("Go migration service listening on ", *listen)
	if err = server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
