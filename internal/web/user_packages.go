package web

import (
	"context"
	"errors"
	"github.com/Angasky/dingzhi-ban/internal/config"
	"net/http"
	"slices"
	"time"
)

func (s *Server) exclusiveUserPackage(userID, profile string) (panelUser, error) {
	users, e := s.users()
	if e != nil {
		return panelUser{}, e
	}
	var selected panelUser
	for _, u := range users {
		if u.ID == userID {
			selected = u
		}
		if u.ID != userID && slices.Contains(u.Profiles, profile) {
			return panelUser{}, errors.New("这份订阅被多个用户共享，请先给该用户分配独立订阅")
		}
	}
	if selected.ID == "" || !slices.Contains(selected.Profiles, profile) {
		return panelUser{}, errors.New("用户未获授权访问此套餐订阅")
	}
	return selected, nil
}
func publicUserExit(p map[string]any) map[string]any {
	v, _ := p["userExit"].(map[string]any)
	if v == nil {
		return map[string]any{"enabled": false}
	}
	return map[string]any{"enabled": true, "status": v["status"], "label": v["label"], "error": v["error"], "servers": v["servers"], "updatedAt": v["updatedAt"]}
}
func (s *Server) userPackagesRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/users/packages" {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == "GET" {
		users, e := s.users()
		if e != nil {
			problem(w, 500, "用户读取失败")
			return true
		}
		id := r.URL.Query().Get("id")
		var u panelUser
		counts := map[string]int{}
		for _, candidate := range users {
			for _, p := range candidate.Profiles {
				counts[p]++
			}
			if candidate.ID == id {
				u = candidate
			}
		}
		if u.ID == "" {
			problem(w, 404, "用户不存在")
			return true
		}
		rows := []map[string]any{}
		for _, profile := range u.Profiles {
			p, e := s.repository.State(profile)
			if e != nil {
				rows = append(rows, map[string]any{"id": profile, "unavailable": true})
				continue
			}
			traffic, e := config.TrafficInfo(p, s.now())
			if e != nil {
				problem(w, 400, e.Error())
				return true
			}
			rows = append(rows, map[string]any{"id": profile, "name": p["name"], "exclusive": counts[profile] == 1, "traffic": traffic, "exit": publicUserExit(p)})
		}
		plans, e := s.repository.Plans()
		if e != nil {
			problem(w, 400, e.Error())
			return true
		}
		respond(w, 200, map[string]any{"user": userView(u), "packages": rows, "plans": plans})
		return true
	}
	if r.Method != "POST" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	var in struct {
		UserID      string `json:"userId"`
		Profile     string `json:"profile"`
		Action      string `json:"action"`
		ExitProfile string `json:"exitProfile"`
		ExitName    string `json:"exitName"`
		PlanID      string `json:"planId"`
		Confirmed   bool   `json:"confirmed"`
		Token       string `json:"token"`
	}
	if readJSON(w, r, &in) != nil || !in.Confirmed {
		problem(w, 400, "请确认套餐操作")
		return true
	}
	s.userAdminMu.Lock()
	defer s.userAdminMu.Unlock()
	u, e := s.exclusiveUserPackage(in.UserID, in.Profile)
	if e != nil {
		problem(w, 409, e.Error())
		return true
	}
	if !u.Enabled && in.Action != "clearExit" && in.Action != "resumeExit" {
		problem(w, 409, "用户已禁用")
		return true
	}
	c, e := s.subscriptionController()
	if e != nil {
		problem(w, 400, e.Error())
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	var result map[string]any
	switch in.Action {
	case "previewCycle":
		result, e = c.PreviewCycleRepair(in.Profile)
	case "repairCycle":
		result, e = c.ApplyCycleRepair(ctx, in.Profile, in.Token)
	case "setExit":
		node, err := s.repository.ProbeNodeConfig(in.ExitProfile, in.ExitName)
		if err != nil {
			e = err
			break
		}
		result, e = c.SetUserExit(ctx, in.Profile, in.UserID, in.ExitName, node, false)
	case "clearExit":
		result, e = c.SetUserExit(ctx, in.Profile, in.UserID, "", nil, false)
	case "resumeExit":
		result, e = c.SetUserExit(ctx, in.Profile, in.UserID, "", nil, true)
	case "resetUsage":
		result, e = c.ResetPackageUsage(ctx, in.Profile)
	case "applyPlan":
		result, e = c.ApplyPlan(ctx, in.Profile, in.PlanID)
	default:
		e = errors.New("套餐操作无效")
	}
	if e != nil {
		problem(w, 400, e.Error())
	} else {
		respond(w, 200, result)
	}
	return true
}

// userAdminMu serializes this guard with exclusive exit changes.
func (s *Server) checkPackageAssignment(id string, profiles []string, removing bool) error {
	rows, e := s.repository.Profiles()
	if e != nil {
		return e
	}
	for _, row := range rows {
		profile := row["id"].(string)
		p, e := s.repository.State(profile)
		if e != nil {
			return e
		}
		owner, _ := p["packageOwner"].(string)
		if owner == "" {
			continue
		}
		if slices.Contains(profiles, profile) && owner != id {
			return errors.New("该订阅已绑定其他用户的专属出口，不能共享授权")
		}
		if owner == id && (removing || !slices.Contains(profiles, profile)) {
			return errors.New("请先清除该用户的套餐出口，再删除用户或移除订阅授权")
		}
	}
	return nil
}
