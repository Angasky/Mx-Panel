package web

import (
	"context"
	"github.com/Angasky/dingzhi-ban/internal/links"
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
		Mode  string   `json:"mode"`
	}
	if readJSON(w, r, &in) != nil || (in.Mode != "" && in.Mode != "tcp" && in.Mode != "tls") {
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
	budget := 18 * time.Second
	if in.Mode == "tls" {
		budget = 28 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), budget)
	defer cancel()
	results := make([]config.Document, len(targets))
	pending := []netprobe.Target{}
	tlsPending := []netprobe.TLSTarget{}
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
		if in.Mode == "tls" {
			reason := ""
			switch {
			case n["reality"] == true:
				reason = "reality-unsupported"
			case n["tls"] != true && !(n["type"] == "trojan" && n["tls"] == nil):
				reason = "not-tls"
			}
			if reason != "" {
				results[i]["tlsError"] = reason
				pending = append(pending, target)
				continue
			}
			sni, _ := n["sni"].(string)
			serverName, _ := n["servername"].(string)
			if sni != "" && serverName != "" && sni != serverName {
				results[i]["error"] = "invalid-target"
				continue
			}
			if sni == "" {
				sni = serverName
			}
			if sni == "" {
				sni = host
			}
			var alpn []string
			if n["alpn"] != nil {
				values, parseErr := links.ALPNValues(n["alpn"], false)
				err = parseErr
				for _, v := range values {
					alpn = append(alpn, v.(string))
				}
				if err != nil {
					results[i]["error"] = "invalid-target"
					continue
				}
			}
			tlsPending = append(tlsPending, netprobe.TLSTarget{Target: target, ServerName: sni, ALPN: alpn})
		} else {
			pending = append(pending, target)
		}
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
	measureTLS := s.measureNodeTLS
	if measureTLS == nil {
		measureTLS = netprobe.MeasureTLS
	}
	for start := 0; start < len(tlsPending) && ctx.Err() == nil; start += 6 {
		for _, r := range measureTLS(ctx, tlsPending[start:min(start+6, len(tlsPending))]) {
			i, e := strconv.Atoi(r.Name)
			if e != nil || i < 0 || i >= len(results) {
				continue
			}
			results[i]["ok"], results[i]["milliseconds"], results[i]["error"], results[i]["time"] = r.OK, r.Milliseconds, r.Error, r.Time
			results[i]["tlsOK"], results[i]["tlsError"], results[i]["tlsMilliseconds"], results[i]["certificateExpires"], results[i]["tlsVersion"] = r.TLSOK, r.TLSError, r.TLSMilliseconds, r.CertificateExpires, r.TLSVersion
		}
	}
	mode := in.Mode
	if mode == "" {
		mode = "tcp"
	}
	respond(w, 200, config.Document{"source": "panel", "method": mode, "results": results})
	return true
}
