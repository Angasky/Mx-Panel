package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

type renewalPreview struct {
	Revision string `json:"revision"`
	Previous string `json:"previous"`
	Next     string `json:"next"`
	Base     string `json:"base"`
	Cycle    string `json:"cycle"`
	Public   bool   `json:"public"`
}

func previewRenewal(m serverMetadata, base string, now time.Time) (renewalPreview, error) {
	v := renewalPreview{Previous: m.Expires, Cycle: m.Cycle, Base: base, Public: m.Public}
	months := map[string]int{"month": 1, "quarter": 3, "half-year": 6, "year": 12}[m.Cycle]
	if months == 0 {
		return v, errors.New("请先保存月、季度、半年或年的计费周期；一次性项目不能自动延长")
	}
	date := m.Expires
	if base == "today" {
		date = now.UTC().Format("2006-01-02")
	} else if base != "expiry" {
		return v, errors.New("续费起算方式无效")
	}
	at, e := time.Parse("2006-01-02", date)
	if e != nil {
		return v, errors.New("请先保存有效到期日期，或选择从今天起算")
	}
	first := time.Date(at.Year(), at.Month()+time.Month(months), 1, 0, 0, 0, 0, time.UTC)
	day := at.Day()
	if max := first.AddDate(0, 1, -1).Day(); day > max {
		day = max
	}
	next := first.AddDate(0, 0, day-1)
	if next.Year() > 2200 {
		return v, errors.New("新到期日期超出支持范围")
	}
	v.Next = next.Format("2006-01-02")
	if m.Expires != "" && v.Next <= m.Expires {
		return v, errors.New("新日期未晚于当前到期日，请选择从原到期日起算")
	}
	raw, _ := json.Marshal(struct {
		Metadata   serverMetadata
		Base, Next string
	}{m, base, v.Next})
	h := sha256.Sum256(raw)
	v.Revision = hex.EncodeToString(h[:])
	return v, nil
}
func (s *Server) renewalRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/servers/renewal" {
		return false
	}
	if r.Method != "GET" && r.Method != "POST" {
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
	base := r.URL.Query().Get("base")
	if base == "" {
		base = "expiry"
	}
	var input struct {
		Revision  string `json:"revision"`
		Confirmed bool   `json:"confirmed"`
	}
	if r.Method == "POST" {
		if readJSON(w, r, &input) != nil || !input.Confirmed || input.Revision == "" {
			problem(w, 400, "请先预览并确认已经完成实际续费")
			return true
		}
	}
	s.metadataMu.Lock()
	defer s.metadataMu.Unlock()
	m, e := s.readMetadata(id)
	if e != nil {
		problem(w, 500, "续费信息读取失败")
		return true
	}
	v, e := previewRenewal(m, base, s.now())
	if e != nil {
		problem(w, 400, e.Error())
		return true
	}
	if r.Method == "POST" {
		if input.Revision != v.Revision {
			problem(w, 409, "信息已改变或该次续费已登记，请重新预览；未重复延长")
			return true
		}
		m.Expires = v.Next
		if e = s.writeMetadata(id, m); e != nil {
			problem(w, 500, "续费登记保存失败")
			return true
		}
	}
	respond(w, 200, v)
	return true
}
