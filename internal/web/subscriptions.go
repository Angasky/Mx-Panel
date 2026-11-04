package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/billing"
	"github.com/Angasky/dingzhi-ban/internal/releaseupdate"
	"github.com/Angasky/dingzhi-ban/internal/subscriptions"
)

var subscriptionControllers sync.Map
var subscriptionControllersMu sync.Mutex

func (s *Server) subscriptionController() (*subscriptions.Controller, error) {
	if v, ok := subscriptionControllers.Load(s.repository); ok {
		return v.(*subscriptions.Controller), nil
	}
	subscriptionControllersMu.Lock()
	defer subscriptionControllersMu.Unlock()
	if v, ok := subscriptionControllers.Load(s.repository); ok {
		return v.(*subscriptions.Controller), nil
	}
	backend, err := s.remoteManager()
	if err != nil {
		return nil, err
	}
	controller := subscriptions.New(s.repository, backend)
	subscriptionControllers.Store(s.repository, controller)
	return controller, nil
}
func (s *Server) RunBackground(ctx context.Context) error {
	c, err := s.subscriptionController()
	if err != nil {
		return err
	}
	backend, err := s.remoteManager()
	if err != nil {
		return err
	}
	backend.SetJobContext(ctx)
	if err = backend.RecoverInstallJobs(); err != nil {
		return err
	}
	if err := c.Start(ctx); err != nil {
		return err
	}
	if releaseupdate.ValidVersion(s.options.Version) {
		go s.updates.watch(ctx, goUpdateCheckInterval, s.now, fetchGoRelease)
	}
	return nil
}

func (s *Server) subscriptionRoutes(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == "/admin/api/servers/inbounds" && (r.Method == "PUT" || r.Method == "DELETE") {
		var input struct {
			ServerID  string         `json:"serverId"`
			InboundID int            `json:"inboundId"`
			Inbound   map[string]any `json:"inbound"`
			Expected  string         `json:"expectedIdentity"`
		}
		if err := readJSON(w, r, &input); err != nil {
			problem(w, 400, err.Error())
			return true
		}
		c, err := s.subscriptionController()
		if err != nil {
			problem(w, 400, err.Error())
			return true
		}
		ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
		defer cancel()
		result, err := c.WriteInbound(ctx, input.ServerID, input.InboundID, input.Inbound, input.Expected, r.Method == "DELETE")
		if err != nil {
			problem(w, 400, err.Error())
		} else {
			respond(w, 200, result)
		}
		return true
	}
	if r.Method == "POST" && r.URL.Path == "/admin/api/servers/users/targets" {
		var input struct {
			ServerID   string `json:"serverId"`
			InboundIDs []int  `json:"inboundIds"`
		}
		if err := readJSON(w, r, &input); err != nil {
			problem(w, 400, err.Error())
			return true
		}
		profiles, err := s.repository.ImportTargets(input.ServerID, input.InboundIDs)
		if err != nil {
			problem(w, 400, err.Error())
		} else {
			respond(w, 200, map[string]any{"profiles": profiles})
		}
		return true
	}
	path := r.URL.Path
	read := path == "/admin/api/traffic" && r.Method == "GET"
	write := r.Method == "POST" && (path == "/admin/api/servers/relay" || path == "/admin/api/servers/inbounds" || path == "/admin/api/servers/users/batch" || path == "/admin/api/servers/users" || path == "/admin/api/traffic/sync" || path == "/admin/api/servers/multiplier")
	policy := r.Method == "PUT" && (path == "/admin/api/traffic" || path == "/admin/api/traffic/plan" || path == "/admin/api/traffic/plans" || path == "/admin/api/traffic/plans/delete" || path == "/admin/api/servers/multiplier" || path == "/admin/api/traffic/bindings/cleanup" || path == "/admin/api/traffic/bindings/remove" || path == "/admin/api/traffic/bindings/migrate")
	if !read && !write && !policy {
		return false
	}
	c, err := s.subscriptionController()
	if err != nil {
		problem(w, 400, err.Error())
		return true
	}
	profile := r.Header.Get("X-Profile")
	if read {
		result, err := c.Info(profile)
		if err != nil {
			problem(w, 400, err.Error())
		} else {
			respond(w, 200, result)
		}
		return true
	}
	var payload map[string]any
	if readJSON(w, r, &payload) != nil || payload == nil {
		problem(w, 400, "请求 JSON 必须为对象")
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	var result map[string]any
	if path == "/admin/api/servers/relay" {
		result, err = c.CreateRelay(ctx, profile, stringField(payload, "serverId"), payload)
	} else if path == "/admin/api/servers/inbounds" {
		result, err = c.CreateInbound(ctx, profile, stringField(payload, "serverId"), payload)
	} else if path == "/admin/api/traffic/bindings/cleanup" {
		result, err = c.CleanupBindings(ctx, profile, payload["confirmed"] == true)
	} else if path == "/admin/api/traffic/bindings/remove" || path == "/admin/api/traffic/bindings/migrate" {
		index, ok := payload["recordIndex"].(json.Number)
		var n int
		if ok {
			n, err = strconv.Atoi(string(index))
		} else {
			err = errors.New("绑定记录索引必须为整数")
		}
		if err == nil {
			if path == "/admin/api/traffic/bindings/migrate" {
				result, err = c.MigrateLegacyBinding(ctx, profile, n, stringField(payload, "recordToken"), payload["confirmed"] == true)
			} else {
				result, err = c.RemoveBinding(ctx, profile, n, stringField(payload, "recordToken"), payload["confirmed"] == true)
			}
		}
	} else if policy && path != "/admin/api/servers/multiplier" {
		if path == "/admin/api/traffic" {
			result, err = c.EditTraffic(ctx, profile, payload)
		} else if path == "/admin/api/traffic/plan" {
			result, err = c.ApplyPlan(ctx, profile, stringField(payload, "planId"))
		} else {
			var plan map[string]any
			if path == "/admin/api/traffic/plans" {
				plan, err = s.repository.SavePlan(payload)
			} else {
				err = s.repository.DeletePlan(stringField(payload, "id"))
			}
			if err == nil {
				result, err = c.Info(profile)
			}
			if err == nil {
				result = map[string]any{"traffic": result}
				if plan != nil {
					result["plan"] = plan
				}
			}
		}
		if err == nil && (path == "/admin/api/traffic" || path == "/admin/api/traffic/plan") {
			result = map[string]any{"traffic": result}
		}
	} else if path == "/admin/api/traffic/sync" {
		result, err = c.Sync(ctx, profile)
	} else {
		server := stringField(payload, "serverId")
		parseID := func(v any) (int, error) {
			n, err := strconv.Atoi(anyText(v))
			if err != nil || n < 1 {
				return 0, errors.New("入站 ID 必须为正整数")
			}
			return n, nil
		}
		if path == "/admin/api/servers/multiplier" {
			var id int
			var units int64
			id, err = parseID(payload["inboundId"])
			if err == nil {
				units, err = billing.MultiplierUnits(anyText(payload["multiplier"]))
			}
			if err == nil {
				result, err = c.SetMultiplier(ctx, profile, server, id, units)
				if err == nil {
					var info map[string]any
					info, err = c.Info(profile)
					if err == nil {
						result = map[string]any{"node": result, "traffic": info}
					}
				}
			}
		} else {
			ids := []int{}
			if path == "/admin/api/servers/users" {
				if payload["inboundId"] == nil {
					result, err = c.CreateInbound(ctx, profile, server, payload)
					if err != nil {
						problem(w, 400, err.Error())
					} else {
						result["ok"] = true
						respond(w, 200, result)
					}
					return true
				}
				var id int
				id, err = parseID(payload["inboundId"])
				if err == nil {
					ids = append(ids, id)
				}
			} else {
				values, ok := payload["inboundIds"].([]any)
				if !ok {
					err = errors.New("请选择入站")
				}
				for _, v := range values {
					if _, ok := v.(json.Number); !ok {
						err = errors.New("入站 ID 必须为整数")
						break
					}
					var id int
					id, err = parseID(v)
					if err != nil {
						break
					}
					ids = append(ids, id)
				}
			}
			if err == nil {
				result, err = c.Batch(ctx, profile, server, ids)
			}
			if err == nil && path == "/admin/api/servers/users" {
				results := result["results"].([]any)
				item := results[0].(map[string]any)
				if item["ok"] != true {
					err = errors.New(stringField(item, "error"))
				} else {
					result = map[string]any{"added": item["added"], "existing": item["existing"], "bound": true, "enforcementEnabled": true}
					for _, key := range []string{"runtimeVerified", "runtimeRepaired", "warning"} {
						if value, exists := item[key]; exists {
							result[key] = value
						}
					}
				}
			}
		}
	}
	if err != nil {
		problem(w, 400, err.Error())
	} else {
		result["ok"] = true
		respond(w, 200, result)
	}
	return true
}
