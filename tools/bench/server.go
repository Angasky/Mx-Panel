// Isolated HTTP benchmark host. Uses the production handler without periodic
// update, SSH or accounting workers; do not expose this listener to the network.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/web"
)

func main() {
	root := flag.String("root", "", "isolated fixture directory")
	flag.Parse()
	if *root == "" {
		log.Fatal("fixture directory required")
	}
	handler, err := web.New(web.Options{Root: *root, AuthFile: *root + "/auth.json", TrustLoopbackProxy: true})
	if err != nil {
		log.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"port": listener.Addr().(*net.TCPAddr).Port, "runtimeVersion": runtime.Version()})
	service := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: time.Minute}
	log.Fatal(service.Serve(listener))
}
