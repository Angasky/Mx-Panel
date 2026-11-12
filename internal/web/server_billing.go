package web

import (
	"github.com/Angasky/dingzhi-ban/internal/monitorhistory"
	"net/http"
)

func (s *Server) billingRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/servers/billing" {
		return false
	}
	if r.Method != "GET" && r.Method != "PUT" && r.Method != "DELETE" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	id := r.URL.Query().Get("id")
	manager, e := s.remoteManager()
	if e != nil {
		problem(w, 500, "服务器数据不可用")
		return true
	}
	if _, e = manager.Record(id); e != nil {
		problem(w, 404, "服务器不存在")
		return true
	}
	now := s.now()
	if r.Method == "PUT" {
		var c monitorhistory.BillingConfig
		if readJSON(w, r, &c) != nil {
			problem(w, 400, "周期设置格式无效")
			return true
		}
		if e = s.history.SetBilling(id, &c, now); e != nil {
			problem(w, 400, e.Error())
			return true
		}
	} else if r.Method == "DELETE" {
		if e = s.history.SetBilling(id, nil, now); e != nil {
			problem(w, 500, "清除周期设置失败")
			return true
		}
	}
	state, e := s.history.Read(id, now)
	if e != nil {
		problem(w, 500, "流量记录读取失败")
		return true
	}
	respond(w, 200, monitorhistory.BillingSummary(state, now))
	return true
}
