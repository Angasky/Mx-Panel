package web

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/config"
)

func (s *Server) flagRoutes(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != "POST" || r.URL.Path != "/admin/api/nodes/flags" {
		return false
	}
	var input struct{ Names any }
	if err := readJSON(w, r, &input); err != nil {
		problem(w, 400, err.Error())
		return true
	}
	id := r.Header.Get("X-Profile")
	targets, err := s.repository.FlagTargets(id, input.Names)
	if err != nil {
		problem(w, 400, err.Error())
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	results := map[string]config.FlagCountry{}
	servers := map[string]bool{}
	for _, target := range targets {
		servers[target.Server] = true
	}
	var mu sync.Mutex
	var group sync.WaitGroup
	jobs := make(chan string)
	for worker := 0; worker < 8; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for server := range jobs {
				country, err := s.countryLookup(ctx, server)
				result := config.FlagCountry{Code: country.Code, IP: country.IP}
				if err != nil {
					result.Error = err.Error()
				}
				mu.Lock()
				results[server] = result
				mu.Unlock()
			}
		}()
	}
	for server := range servers {
		if ctx.Err() != nil {
			break
		}
		jobs <- server
	}
	close(jobs)
	group.Wait()
	if ctx.Err() != nil {
		problem(w, 408, "国家标识查询已取消，未保存修改")
		return true
	}
	result, err := s.repository.ApplyCountryFlags(id, targets, results)
	if err != nil {
		problem(w, 400, err.Error())
	} else {
		result["ok"] = true
		respond(w, 200, result)
	}
	return true
}
