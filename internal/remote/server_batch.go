package remote

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

type BatchInstallItem struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
	Job      string `json:"job,omitempty"`
	Revision string `json:"revision,omitempty"`
}
type BatchInstall struct {
	ID            string             `json:"id"`
	Status        string             `json:"status"`
	StopOnFailure bool               `json:"stopOnFailure"`
	Items         []BatchInstallItem `json:"items"`
	Created       int64              `json:"created"`
}

func batchRecordRevision(row Record) string {
	b, _ := json.Marshal(row)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (m *Manager) readInstallBatch() (BatchInstall, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, e := m.load()
	if e != nil {
		return BatchInstall{}, e
	}
	var batch BatchInstall
	if data["installBatch"] == nil {
		return BatchInstall{Status: "idle", Items: []BatchInstallItem{}}, nil
	}
	b, e := json.Marshal(data["installBatch"])
	if e != nil {
		return batch, e
	}
	e = json.Unmarshal(b, &batch)
	return batch, e
}
func (m *Manager) writeInstallBatch(batch BatchInstall) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, e := m.load()
	if e != nil {
		return e
	}
	data["installBatch"] = batch
	return m.flush(data)
}

// batchMu serializes queue transitions; the existing install worker owns each
// actual job. Never replay an in-flight install after process restart.
func (m *Manager) InstallBatch(ids []string, confirmed, stopOnFailure, cancel bool) (BatchInstall, error) {
	m.batchMu.Lock()
	defer m.batchMu.Unlock()
	batch, e := m.readInstallBatch()
	if e != nil {
		return batch, e
	}
	if !m.batchRunning && (batch.Status == "running" || batch.Status == "stopping") {
		batch.Status = "interrupted"
		for i := range batch.Items {
			if batch.Items[i].Status == "pending" || batch.Items[i].Status == "running" {
				batch.Items[i].Status = "interrupted"
				batch.Items[i].Error = "面板重启，未自动重放；请查看原安装日志后重新选择"
			}
		}
		if e = m.writeInstallBatch(batch); e != nil {
			return batch, e
		}
	}
	if cancel {
		if m.batchRunning {
			batch.Status = "stopping"
			e = m.writeInstallBatch(batch)
		}
		return batch, e
	}
	if ids == nil {
		return batch, nil
	}
	if !confirmed || len(ids) == 0 || len(ids) > 20 {
		return batch, errors.New("请选择 1–20 台服务器并确认批量安装")
	}
	if m.batchRunning {
		return batch, errors.New("已有安装批次正在执行，请先等待完成或停止后续派发")
	}
	seen := map[string]bool{}
	items := []BatchInstallItem{}
	for _, id := range ids {
		if seen[id] {
			return batch, errors.New("服务器选择重复")
		}
		seen[id] = true
		row, e := m.Record(id)
		if e != nil {
			return batch, e
		}
		kind := value(row["installType"])
		if row["agentOnly"] == true || row["connectionMode"] != "install" || (kind != "xray" && kind != "sing-box") {
			return batch, errors.New(value(row["name"]) + "：仅支持已授权且处于安装模式的 Xray / sing-box；请先批量编辑或连接设置")
		}
		if _, e = m.connectionRecord(row); e != nil {
			return batch, e
		}
		items = append(items, BatchInstallItem{ID: id, Name: value(row["name"]), Kind: kind, Status: "pending", Revision: batchRecordRevision(row)})
	}
	raw := make([]byte, 12)
	if _, e = rand.Read(raw); e != nil {
		return batch, e
	}
	batch = BatchInstall{ID: hex.EncodeToString(raw), Status: "running", StopOnFailure: stopOnFailure, Items: items, Created: time.Now().Unix()}
	if e = m.writeInstallBatch(batch); e != nil {
		return batch, e
	}
	m.batchRunning = true
	go m.runInstallBatch(batch.ID)
	return batch, nil
}
func (m *Manager) runInstallBatch(id string) {
	defer func() { m.batchMu.Lock(); m.batchRunning = false; m.batchMu.Unlock() }()
	for {
		m.batchMu.Lock()
		batch, e := m.readInstallBatch()
		if e != nil || batch.ID != id {
			m.batchMu.Unlock()
			return
		}
		index := -1
		for i := range batch.Items {
			if batch.Items[i].Status == "pending" {
				index = i
				break
			}
		}
		if batch.Status == "stopping" || index < 0 {
			if batch.Status == "stopping" {
				batch.Status = "stopped"
				for i := range batch.Items {
					if batch.Items[i].Status == "pending" {
						batch.Items[i].Status = "skipped"
					}
				}
			} else {
				batch.Status = "completed"
				for _, v := range batch.Items {
					if v.Status == "failed" {
						batch.Status = "completed_with_errors"
					}
				}
			}
			m.writeInstallBatch(batch)
			m.batchMu.Unlock()
			return
		}
		item := &batch.Items[index]
		// Persist dispatch intent before starting; a crash becomes interrupted.
		item.Status = "running"
		if m.writeInstallBatch(batch) != nil {
			m.batchMu.Unlock()
			return
		}
		job, e := m.startInstallExpected(item.ID, true, item.Revision)
		if e != nil {
			item.Status = "failed"
			item.Error = e.Error()
		} else {
			item.Job = value(job["id"])
		}
		if m.writeInstallBatch(batch) != nil {
			m.batchMu.Unlock()
			return
		}
		m.batchMu.Unlock()
		if e == nil {
			for {
				job, e = m.InstallJob(item.Job)
				if e != nil || job["status"] != "running" {
					break
				}
				time.Sleep(time.Second)
			}
		}
		m.batchMu.Lock()
		latest, readErr := m.readInstallBatch()
		if readErr != nil || latest.ID != id {
			m.batchMu.Unlock()
			return
		}
		if e != nil {
			latest.Items[index].Status = "failed"
			latest.Items[index].Error = e.Error()
		} else if job["status"] == "succeeded" {
			latest.Items[index].Status = "succeeded"
		} else {
			latest.Items[index].Status = "failed"
			latest.Items[index].Error = value(job["error"])
			if latest.Items[index].Error == "" {
				latest.Items[index].Error = "安装未成功，请查看任务日志"
			}
		}
		if latest.Items[index].Status == "failed" && latest.StopOnFailure {
			latest.Status = "stopping"
		}
		e = m.writeInstallBatch(latest)
		m.batchMu.Unlock()
		if e != nil {
			return
		}
	}
}
