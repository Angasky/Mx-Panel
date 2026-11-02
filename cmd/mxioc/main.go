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

func main() {
	listen := flag.String("listen", "127.0.0.1:62578", "listen address; development port differs from Python")
	root := flag.String("root", "/opt/mxioc-rule-manager", "application data directory")
	auth := flag.String("auth", "/etc/mxioc-rule-manager.auth.json", "existing administrator credential file")
	proxy := flag.Bool("trust-loopback-proxy", false, "trust HTTPS forwarding only from loopback reverse proxy")
	local := flag.Bool("local-development", false, "allow loopback HTTP for isolated development only")
	flag.Parse()
	handler, err := web.New(web.Options{Root: *root, AuthFile: *auth, TrustLoopbackProxy: *proxy, LocalDevelopment: *local})
	if err != nil {
		log.Fatal("startup validation failed: ", err)
	}
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
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
