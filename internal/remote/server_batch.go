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
	Concurrency   int                `json:"concurrency"`
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
func (m *Manager) InstallBatch(ids []string, confirmed, stopOnFailure, cancel bool, limits ...int) (BatchInstall, error) {
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
	concurrency := 5
	if len(limits) > 0 && limits[0] != 0 {
		concurrency = limits[0]
	}
	if concurrency < 1 || concurrency > 20 {
		return batch, errors.New("安装并发数须为 1–20")
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
	batch = BatchInstall{Concurrency: concurrency, ID: hex.EncodeToString(raw), Status: "running", StopOnFailure: stopOnFailure, Items: items, Created: time.Now().Unix()}
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
		done, err := m.stepInstallBatch(id)
		if err != nil || done {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// Refresh every active job before dispatching more, so failure-stop prevents
// new starts while allowing all already-running hosts to finish independently.
func (m *Manager) stepInstallBatch(id string) (bool, error) {
	m.batchMu.Lock()
	defer m.batchMu.Unlock()
	batch, err := m.readInstallBatch()
	if err != nil {
		return true, err
	}
	if batch.ID != id {
		return true, nil
	}
	limit := batch.Concurrency
	if limit < 1 {
		limit = 1
	}
	if limit > 20 {
		limit = 20
	}
	running := 0
	for i := range batch.Items {
		item := &batch.Items[i]
		if item.Status != "running" {
			continue
		}
		job, e := m.InstallJob(item.Job)
		if e == nil && (job["status"] == "running" || job["status"] == "queued") {
			running++
			continue
		}
		if e != nil {
			item.Status = "failed"
			item.Error = e.Error()
		} else if job["status"] == "succeeded" {
			item.Status = "succeeded"
		} else {
			item.Status = "failed"
			item.Error = value(job["error"])
			if item.Error == "" {
				item.Error = "安装未成功，请查看任务日志"
			}
		}
		if item.Status == "failed" && batch.StopOnFailure {
			batch.Status = "stopping"
		}
	}
	if batch.Status != "stopping" {
		for i := range batch.Items {
			item := &batch.Items[i]
			if item.Status != "pending" {
				continue
			}
			if running >= limit {
				break
			}
			// Durable intent before start. Never replay this item after restart.
			item.Status = "running"
			if e := m.writeInstallBatch(batch); e != nil {
				return true, e
			}
			job, e := m.startInstallExpected(item.ID, true, item.Revision)
			if errors.Is(e, ErrInstallCapacity) {
				item.Status = "pending"
				break
			}
			if e != nil {
				item.Status = "failed"
				item.Error = e.Error()
				if batch.StopOnFailure {
					batch.Status = "stopping"
					break
				}
			} else {
				item.Job = value(job["id"])
				running++
			}
			if e := m.writeInstallBatch(batch); e != nil {
				return true, e
			}
		}
	}
	pending := 0
	for i := range batch.Items {
		if batch.Items[i].Status == "pending" {
			if batch.Status == "stopping" {
				batch.Items[i].Status = "skipped"
			} else {
				pending++
			}
		}
	}
	done := running == 0 && pending == 0
	if done {
		if batch.Status == "stopping" {
			batch.Status = "stopped"
		} else {
			batch.Status = "completed"
			for _, item := range batch.Items {
				if item.Status == "failed" {
					batch.Status = "completed_with_errors"
					break
				}
			}
		}
	}
	if e := m.writeInstallBatch(batch); e != nil {
		return true, e
	}
	return done, nil
}
