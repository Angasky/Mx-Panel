package web

import (
	"errors"
	"github.com/Angasky/dingzhi-ban/internal/subscriptions"
	"net/http"
)

func preferredClient(value string) string {
	if value == "" {
		return "clash"
	}
	return value
}
func (s *Server) memberPreferences(w http.ResponseWriter, r *http.Request, u panelUser) {
	if r.Method == "GET" {
		respond(w, 200, map[string]any{"client": preferredClient(u.PreferredClient), "clients": subscriptions.ClientChoices()})
		return
	}
	if r.Method != "PUT" {
		problem(w, 405, "请求方法不支持")
		return
	}
	var in struct {
		Client   string `json:"client"`
		Expected string `json:"expected"`
	}
	if readJSON(w, r, &in) != nil || !subscriptions.ValidClientChoice(in.Client) {
		problem(w, 400, "请选择有效客户端")
		return
	}
	err := s.updateUsers(func(doc map[string]any) error {
		users, e := decodeUsers(doc)
		if e != nil {
			return e
		}
		for i := range users {
			v := &users[i]
			if v.ID != u.ID {
				continue
			}
			session, ok := v.Sessions[userDigest(r)]
			if !v.Enabled || !ok || !s.now().Before(session.Expires) {
				return errors.New("登录状态已变化，请重新登录")
			}
			if preferredClient(v.PreferredClient) != in.Expected {
				return errors.New("首选客户端已变化，请刷新后重试")
			}
			v.PreferredClient = in.Client
			doc["users"] = users
			return nil
		}
		return errors.New("用户已不存在")
	})
	if err != nil {
		problem(w, 409, err.Error())
		return
	}
	respond(w, 200, map[string]any{"client": in.Client})
}
