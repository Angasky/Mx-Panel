// mxioc-agent publishes Linux resource observations. It accepts no remote commands.
package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/remote"
	"golang.org/x/net/websocket"
)

type configuration struct {
	URL         string `json:"url"`
	Token       string `json:"token"`
	Mode        string `json:"mode"`
	Listen      string `json:"listen,omitempty"`
	Certificate string `json:"certificate,omitempty"`
	Key         string `json:"key,omitempty"`
}

func main() {
	path := flag.String("config", "/etc/mxioc-agent.json", "0600 Agent configuration")
	local := flag.Bool("local-development", false, "allow loopback HTTP for isolated tests")
	check := flag.Bool("check", false, "validate configuration without starting service")
	flag.Parse()
	if e := run(*path, *local, *check); e != nil {
		log.Fatal(e)
	}
}
func run(path string, local, check bool) error {
	info, e := os.Stat(path)
	if e != nil {
		return errors.New("Agent 配置读取失败")
	}
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("Agent 配置必须设置为 0600")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return errors.New("Agent 配置读取失败")
	}
	var c configuration
	if len(b) > 65536 || json.Unmarshal(b, &c) != nil || len(c.Token) != 43 {
		return errors.New("Agent 配置格式无效")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(c.Token)
	if err != nil || len(decoded) != 32 {
		return errors.New("Agent 令牌格式无效")
	}
	if c.Mode == "pull" {
		if c.Listen == "" {
			c.Listen = "127.0.0.1:62579"
		}
		host, _, err := net.SplitHostPort(c.Listen)
		if err != nil {
			return errors.New("Pull 监听地址无效")
		}
		if !(local && net.ParseIP(host).IsLoopback()) {
			if _, err = tls.LoadX509KeyPair(c.Certificate, c.Key); err != nil {
				return errors.New("Pull TLS 证书或私钥无效")
			}
		}
		if check {
			return nil
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if c.Mode == "pull" {
		return servePull(ctx, c, local)
	}
	if c.Mode != "auto" && c.Mode != "websocket" && c.Mode != "http" {
		return errors.New("mode 必须为 auto、websocket、http 或 pull")
	}
	endpoint, e := url.Parse(c.URL)
	if e != nil || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || !(endpoint.Scheme == "https" || local && endpoint.Scheme == "http" && net.ParseIP(endpoint.Hostname()).IsLoopback()) || !strings.HasPrefix(endpoint.Path, "/sub/agent/") {
		return errors.New("Agent 主控地址必须为有效 HTTPS Agent 接口")
	}
	if check {
		return nil
	}
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("Agent 不跟随重定向") }}
	var ws *websocket.Conn
	defer func() {
		if ws != nil {
			ws.Close()
		}
	}()
	nextWS := time.Time{}
	for {
		if ctx.Err() != nil {
			return nil
		}
		sample, e := remote.CollectAgentSample(ctx)
		if e == nil {
			payload := map[string]string{"sample": sample}
			sent := false
			if c.Mode != "http" && (ws != nil || time.Now().After(nextWS)) {
				if ws == nil {
					address := *endpoint
					if address.Scheme == "https" {
						address.Scheme = "wss"
					} else {
						address.Scheme = "ws"
					}
					cfg, err := websocket.NewConfig(address.String(), endpoint.Scheme+"://"+endpoint.Host)
					if err == nil {
						cfg.Header.Set("Authorization", "Bearer "+c.Token)
						cfg.Dialer = &net.Dialer{Timeout: 10 * time.Second}
						ws, err = websocket.DialConfig(cfg)
					}
					if err != nil {
						nextWS = time.Now().Add(5 * time.Minute)
					}
				}
				if ws != nil {
					ws.SetDeadline(time.Now().Add(20 * time.Second))
					ws.MaxPayloadBytes = 4096
					e = websocket.JSON.Send(ws, payload)
					var ack struct {
						OK bool `json:"ok"`
					}
					if e == nil {
						e = websocket.JSON.Receive(ws, &ack)
					}
					if e == nil && ack.OK {
						sent = true
					} else {
						ws.Close()
						ws = nil
						nextWS = time.Now().Add(5 * time.Minute)
					}
				}
			}
			if !sent && c.Mode != "websocket" {
				raw, _ := json.Marshal(payload)
				req, err := http.NewRequestWithContext(ctx, "POST", c.URL, bytes.NewReader(raw))
				if err == nil {
					req.Header.Set("Authorization", "Bearer "+c.Token)
					req.Header.Set("Content-Type", "application/json")
					resp, err := client.Do(req)
					if err == nil {
						sent = resp.StatusCode == 200
						resp.Body.Close()
					}
				}
			}
			if !sent && ctx.Err() == nil {
				log.Print("采样发送失败，将自动重试（请检查连接和凭据）")
			}
		} else if ctx.Err() == nil {
			log.Print("本机采样失败，将自动重试")
		}
		timer := time.NewTimer(15 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
func servePull(ctx context.Context, c configuration, local bool) error {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:62579"
	}
	host, _, e := net.SplitHostPort(c.Listen)
	if e != nil {
		return errors.New("Pull 监听地址无效")
	}
	plain := local && net.ParseIP(host).IsLoopback()
	if !plain && (c.Certificate == "" || c.Key == "") {
		return errors.New("Pull 模式必须配置 TLS 证书和私钥")
	}
	slots := make(chan struct{}, 2)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path != "/metrics" || r.Method != "GET" {
			http.NotFound(w, r)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+c.Token)) != 1 {
			http.Error(w, "forbidden", 403)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "busy", 429)
			return
		}
		sample, e := remote.CollectAgentSample(r.Context())
		if e != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"sample": sample})
	})
	server := &http.Server{Addr: c.Listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
	}()
	if plain {
		e = server.ListenAndServe()
	} else {
		e = server.ListenAndServeTLS(c.Certificate, c.Key)
	}
	if e == http.ErrServerClosed {
		<-done
		return nil
	}
	return errors.New("Pull 服务启动失败")
}
