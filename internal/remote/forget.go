package remote

import "errors"

// ForgetServer removes this controller's registry entries without connecting to
// the host. A repository transaction coordinates local binding detachment.
func (m *Manager) ForgetServer(id string, detach func(Record, func() error) (Record, error)) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := m.load()
	if err != nil {
		return nil, err
	}
	record, err := find(data, id)
	if err != nil {
		return nil, err
	}
	if len(m.operations[id]) > 0 {
		return nil, errors.New("服务器操作进行中，请稍后重试")
	}
	for _, v := range data["jobs"].([]any) {
		job, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("安装任务记录损坏")
		}
		if job["serverId"] == id && job["status"] == "running" {
			return nil, errors.New("安装任务进行中，请稍后重试")
		}
	}
	for _, key := range []string{"servers", "jobs"} {
		keep := []any{}
		field := "id"
		if key == "jobs" {
			field = "serverId"
		}
		for _, v := range data[key].([]any) {
			row, ok := v.(map[string]any)
			if !ok {
				return nil, errors.New("服务器注册表记录损坏")
			}
			if row[field] != id {
				keep = append(keep, v)
			}
		}
		data[key] = keep
	}
	committed := false
	result, err := detach(record, func() error {
		if committed {
			return errors.New("服务器移除已提交")
		}
		if err := m.flush(data); err != nil {
			return err
		}
		committed = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !committed {
		return nil, errors.New("服务器移除未提交")
	}
	delete(m.panels, id)
	delete(m.operations, id)
	return result, nil
}
