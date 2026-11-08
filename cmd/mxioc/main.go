package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/releaseupdate"
	"github.com/Angasky/dingzhi-ban/internal/web"
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
	applyRelease := flag.String("apply-release", "", "run the queued systemd release update")
	removeService := flag.Bool("remove-service", false, "run the queued service removal with persisted data policy")
	updateJob := flag.String("update-job", "", "queued release update identifier")
	menu := flag.Bool("menu", false, "open mx-p management menu")
	resetUser := flag.String("reset-auth-user", "", "reset credentials from stdin; stop service first")
	gateway := flag.String("gateway", "", "run HTTPS gateway from access config")
	checkAccess := flag.String("check-access", "", "validate HTTPS gateway configuration")
	checkPorts := flag.String("check-access-ports", "", "validate HTTPS gateway ports are available")
	flag.Parse()
	if *checkAccess != "" {
		if _, err := gatewayConfig(*checkAccess); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *checkPorts != "" {
		if err := checkAccessPorts(*checkPorts); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *menu {
		if err := managementMenu(); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *gateway != "" {
		if err := runGateway(*gateway); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *resetUser != "" {
		if os.Geteuid() != 0 {
			log.Fatal("root required")
		}
		if err := resetCredentials(*root, *auth, *resetUser); err != nil {
			log.Fatal(err)
		}
		return
	}
	var updater *releaseupdate.Manager
	if !*local && *root == "/opt/mxioc-rule-manager" && *auth == "/etc/mxioc-rule-manager.auth.json" && releaseupdate.ValidVersion(releaseVersion) {
		updater = releaseupdate.Managed()
	}
	if *removeService {
		if updater == nil || *check || *bootstrapUser != "" || *applyRelease != "" {
			log.Fatal("service removal requires the packaged Linux installation")
		}
		if err := updater.RunUninstall(releaseVersion, *updateJob); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *applyRelease != "" || *updateJob != "" {
		if updater == nil || *check || *bootstrapUser != "" {
			log.Fatal("release update requires the packaged Linux installation")
		}
		if err := updater.Run(releaseVersion, *applyRelease, *updateJob); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *bootstrapUser != "" {
		if *check {
			log.Fatal("--bootstrap-user and --check-data are mutually exclusive")
		}
		if err := bootstrap(*root, *auth, *bootstrapUser, os.Stdin); err != nil {
			log.Fatal("initialization failed: ", err)
		}
		return
	}
	var uninstaller web.ServiceUninstaller
	if updater != nil {
		uninstaller = updater
	}
	handler, err := web.New(web.Options{Root: *root, AuthFile: *auth, AdminHTML: *adminHTML, Version: releaseVersion, TrustLoopbackProxy: *proxy, LocalDevelopment: *local, ReleaseUpdater: updater, ServiceUninstaller: uninstaller})
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
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			log.Print("HTTP shutdown: ", err)
		}
		if err := handler.WaitAccountingStopped(shutdown); err != nil {
			log.Print("accounting shutdown: ", err)
		}
	}()
	log.Print("Go migration service listening on ", *listen)
	if err = server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
	<-shutdownDone
}
