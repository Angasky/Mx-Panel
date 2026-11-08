package web

import (
	"context"
	"crypto/subtle"
	"errors"
	"github.com/Angasky/dingzhi-ban/internal/legacycrypto"
	"github.com/Angasky/dingzhi-ban/internal/releaseupdate"
	"net/http"
)

type dataServiceUninstaller interface {
	StartUninstallWithData(context.Context, string, bool) (*releaseupdate.Job, error)
}
type ServiceUninstaller interface {
	StartUninstall(context.Context, string) (*releaseupdate.Job, error)
}

func (s *Server) uninstallRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/uninstall" {
		return false
	}
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		problem(w, 405, "仅支持 POST")
		return true
	}
	var input struct {
		Username, Password, Confirmation, PurgeConfirmation string
		PurgeData                                           bool
	}
	if err := readJSON(w, r, &input); err != nil {
		problem(w, 400, err.Error())
		return true
	}
	if input.Confirmation != "UNINSTALL" || len(input.Password) > 256 || input.Username == "" {
		problem(w, 400, "请填写当前账号密码及 UNINSTALL 确认")
		return true
	}
	if input.PurgeData && input.PurgeConfirmation != "DELETE ALL DATA" {
		problem(w, 400, "清空数据还需输入 DELETE ALL DATA 确认")
		return true
	}
	if s.options.ServiceUninstaller == nil {
		problem(w, 409, "当前不是标准 Go 服务安装，无法从面板卸载")
		return true
	}
	select {
	case s.hashSlots <- struct{}{}:
	default:
		problem(w, 429, "认证请求过多，请稍后重试")
		return true
	}
	s.mu.Lock()
	auth := s.account
	s.mu.Unlock()
	valid := legacycrypto.VerifyPassword(input.Password, auth.Salt, auth.Hash, auth.Iterations)
	<-s.hashSlots
	valid = valid && subtle.ConstantTimeCompare([]byte(input.Username), []byte(auth.Username)) == 1
	if !valid {
		problem(w, 403, "当前账号或密码错误")
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.account != auth {
		problem(w, 409, "账号已变化，请重新登录")
		return true
	}
	var job *releaseupdate.Job
	var err error
	if input.PurgeData {
		backend, ok := s.options.ServiceUninstaller.(dataServiceUninstaller)
		if !ok {
			problem(w, 409, "当前安装不支持清空数据卸载")
			return true
		}
		job, err = backend.StartUninstallWithData(r.Context(), s.options.Version, true)
	} else {
		job, err = s.options.ServiceUninstaller.StartUninstall(r.Context(), s.options.Version)
	}
	if err != nil {
		code := 503
		if errors.Is(err, releaseupdate.ErrBusy) {
			code = 409
		}
		problem(w, code, err.Error())
		return true
	}
	message := "卸载任务已提交；订阅、账号及远端节点数据会保留"
	if input.PurgeData {
		message = "卸载并清空本地数据任务已提交；远端节点不会删除，本地订阅、账号和备份将删除"
	}
	respond(w, 202, map[string]any{"ok": true, "job": job, "preservedData": !input.PurgeData, "message": message})
	return true
}
