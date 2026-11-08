package web

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/remote"
)

var managers sync.Map
var managersMu sync.Mutex

func (s *Server) remoteManager() (*remote.Manager, error) {
	if value, ok := managers.Load(s.options.Root); ok {
		return value.(*remote.Manager), nil
	}
	managersMu.Lock()
	defer managersMu.Unlock()
	if value, ok := managers.Load(s.options.Root); ok {
		return value.(*remote.Manager), nil
	}
	manager, err := remote.Open(s.options.Root)
	if err != nil {
		return nil, err
	}
	managers.Store(s.options.Root, manager)
	return manager, nil
}
func stringField(payload map[string]any, key string) string {
	value, _ := payload[key].(string)
	return value
}
func (s *Server) remoteRoutes(w http.ResponseWriter, r *http.Request) bool {
	if s.installRoutes(w, r) {
		return true
	}
	if s.coreRoutes(w, r) {
		return true
	}
	if s.sniRoutes(w, r) {
		return true
	}
	if s.certificateRoutes(w, r) {
		return true
	}
	if s.subscriptionRoutes(w, r) {
		return true
	}
	path := r.URL.Path
	method := r.Method
	if path == "/admin/api/servers/probe" && method == "POST" {
		var payload map[string]any
		if err := readJSON(w, r, &payload); err != nil {
			problem(w, 400, err.Error())
			return true
		}
		port := 22
		if value, ok := payload["sshPort"]; ok {
			var err error
			port, err = strconv.Atoi(strings.TrimSpace(anyText(value)))
			if err != nil {
				problem(w, 400, "SSH 端口无效")
				return true
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		pin, err := remote.Probe(ctx, remote.Connection{Host: stringField(payload, "host"), Port: port, User: "root"})
		if err != nil {
			problem(w, 400, err.Error())
		} else {
			respond(w, 200, map[string]any{"fingerprint": pin})
		}
		return true
	}
	supported := path == "/admin/api/servers" && (method == "GET" || method == "POST" || method == "PUT" || method == "DELETE") || (path == "/admin/api/servers/inbounds" || path == "/admin/api/servers/metrics") && method == "GET" || (path == "/admin/api/servers/test" || path == "/admin/api/servers/diagnose" || path == "/admin/api/servers/attach") && method == "POST"
	if !supported {
		return false
	}
	manager, err := s.remoteManager()
	if err != nil {
		problem(w, 400, err.Error())
		return true
	}
	if method == "GET" {
		if path == "/admin/api/servers/metrics" {
			result, err := s.serverMetrics(r.Context(), r.URL.Query().Get("id"))
			if err != nil {
				problem(w, 400, err.Error())
			} else {
				respond(w, 200, result)
			}
			return true
		}
		if path == "/admin/api/servers/inbounds" {
			ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
			defer cancel()
			serverID := r.URL.Query().Get("id")
			observed, err := s.repository.BindingSnapshot(serverID)
			if err != nil {
				problem(w, 400, err.Error())
				return true
			}
			result, err := manager.InboundsWithStats(ctx, serverID)
			if err != nil {
				problem(w, 400, err.Error())
			} else {
				controller, e := s.subscriptionController()
				if e == nil {
					var cleanup map[string]any
					cleanup, e = controller.ReconcileServer(ctx, serverID, result, observed)
					if e == nil {
						result["subscriptionCleanup"] = cleanup
					}
				}
				if e != nil {
					result["subscriptionCleanup"] = map[string]any{"errors": []string{"订阅同步未完成，稍后自动重试"}}
				}
				respond(w, 200, result)
			}
			return true
		}
		servers, err := manager.List()
		if err != nil {
			problem(w, 400, err.Error())
		} else {
			respond(w, 200, map[string]any{"servers": servers})
		}
		return true
	}
	var payload map[string]any
	if err := readJSON(w, r, &payload); err != nil || payload == nil {
		problem(w, 400, "请求 JSON 必须为对象")
		return true
	}
	if path == "/admin/api/servers" {
		id := stringField(payload, "id")
		if method == "DELETE" {
			controller, err := s.subscriptionController()
			var result map[string]any
			if err == nil {
				result, err = controller.ForgetServer(r.Context(), id, payload["detach"] == true)
			}
			if err != nil {
				problem(w, 400, err.Error())
			} else {
				result["ok"] = true
				respond(w, 200, result)
			}
			return true
		}
		controller, err := s.subscriptionController()
		var server map[string]any
		if err == nil {
			server, err = controller.SaveServer(r.Context(), payload)
		}
		if err != nil {
			problem(w, 400, err.Error())
		} else {
			respond(w, 200, map[string]any{"ok": true, "server": server})
		}
		return true
	}
	id := stringField(payload, "id")
	if path == "/admin/api/servers/attach" {
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		result, err := manager.AttachPanel(ctx, id)
		if err != nil {
			problem(w, 400, err.Error())
		} else {
			respond(w, 200, result)
		}
		return true
	}
	connection, err := manager.Connection(id)
	if err != nil {
		problem(w, 400, err.Error())
		return true
	}
	script := "test $(id -u) = 0"
	if path == "/admin/api/servers/diagnose" {
		script = `set +e
printf 'HOST\n'; hostname; uname -a; uptime
printf '\nSERVICES\n'; systemctl --no-pager --full status x-ui xray sing-box 2>&1 | head -100
printf '\nLISTENERS\n'; ss -lntup 2>/dev/null | head -40
printf '\nRECENT LOGS\n'; journalctl --no-pager -u x-ui -u xray -u sing-box -n 60 2>&1
true
`
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	output, err := remote.Execute(ctx, connection, script, 256<<10)
	if path == "/admin/api/servers/diagnose" {
		record, recordErr := manager.Record(id)
		if recordErr == nil {
			for _, key := range []string{"sshPassword", "panelPassword"} {
				if secret, secretErr := manager.Secret(record, key); secretErr == nil && secret != "" {
					output = strings.ReplaceAll(output, secret, "[REDACTED]")
				}
			}
		}
		if err != nil {
			output += "\n" + err.Error()
		}
		respond(w, 200, map[string]any{"log": remote.CleanDiagnosticLog(output)})
		return true
	}
	if err != nil {
		problem(w, 400, "SSH 或 root/sudo 权限检查失败："+err.Error())
		return true
	}
	respond(w, 200, map[string]any{"connected": true, "message": "SSH 和提权权限检查通过"})
	return true
}

func anyText(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case interface{ String() string }:
		return v.String()
	case int:
		return strconv.Itoa(v)
	}
	return ""
}
