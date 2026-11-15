package web

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/netprobe"
)

func nodeTCPSupported(n config.Document) bool {
	switch n["type"] {
	case "ss", "trojan", "vless", "vmess", "snell", "http", "socks5":
	default:
		return false
	}
	switch n["network"] {
	case "quic", "kcp", "udp":
		return false
	}
	return true
}

func (s *Server) nodeProbeRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/nodes/probe" {
		return false
	}
	if r.Method != "POST" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	var in struct {
		Names []string `json:"names"`
	}
	if readJSON(w, r, &in) != nil {
		problem(w, 400, "探测请求无效")
		return true
	}
	targets, err := s.repository.NodeProbeTargets(r.Header.Get("X-Profile"), in.Names)
	if err != nil {
		problem(w, 400, err.Error())
		return true
	}
	if !s.nodeProbeMu.TryLock() {
		problem(w, 429, "已有节点检查进行中，请稍后重试")
		return true
	}
	defer s.nodeProbeMu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 18*time.Second)
	defer cancel()
	results := make([]config.Document, len(targets))
	pending := []netprobe.Target{}
	for i, n := range targets {
		results[i] = config.Document{"name": n["name"], "type": n["type"], "host": n["host"], "port": n["port"], "chain": n["chain"], "ok": false, "milliseconds": nil, "error": "unsupported", "time": time.Now().Unix()}
		if !nodeTCPSupported(n) {
			continue
		}
		host, _ := n["host"].(string)
		port, _ := n["port"].(int)
		target := netprobe.Target{Name: strconv.Itoa(i), Method: "tcp", Host: host, Port: port}
		if netprobe.Validate([]netprobe.Target{target}) != nil {
			results[i]["error"] = "invalid-target"
			continue
		}
		results[i]["error"] = "cancelled"
		pending = append(pending, target)
	}
	measure := s.measureNodeTCP
	if measure == nil {
		measure = netprobe.Measure
	}
	for start := 0; start < len(pending) && ctx.Err() == nil; start += 6 {
		end := min(start+6, len(pending))
		batch := pending[start:end]
		for _, r := range measure(ctx, batch) {
			i, e := strconv.Atoi(r.Name)
			if e != nil || i < 0 || i >= len(results) {
				continue
			}
			results[i]["ok"] = r.OK
			results[i]["milliseconds"] = r.Milliseconds
			results[i]["error"] = r.Error
			results[i]["time"] = r.Time
		}
	}
	respond(w, 200, config.Document{"source": "panel", "method": "tcp", "results": results})
	return true
}
