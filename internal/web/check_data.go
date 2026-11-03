package web

import "fmt"

// CheckData reads all profiles through the normal configuration reader. It does
// not start accounting, connect to servers, migrate files or grant credentials.
func (s *Server) CheckData() error {
	profiles, err := s.repository.Profiles()
	if err != nil {
		return err
	}
	for _, profile := range profiles {
		id, ok := profile["id"].(string)
		if !ok || id == "" {
			return fmt.Errorf("订阅 ID 无效")
		}
		if _, err = s.repository.Snapshot(id); err != nil {
			return fmt.Errorf("订阅 %s 校验失败：%w", id, err)
		}
	}
	return nil
}
