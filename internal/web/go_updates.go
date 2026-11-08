package web

import (
	"context"
	"encoding/json"
	"errors"
	"go/version"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/releaseupdate"
	"github.com/Angasky/dingzhi-ban/internal/storage"
)

const goReleaseRepo = releaseupdate.Repository
const goUpdateCheckInterval = 6 * time.Hour

type goRelease struct {
	Tag   string `json:"tag_name"`
	Draft bool   `json:"draft"`
	Files []struct {
		Name  string `json:"name"`
		State string `json:"state"`
		Size  int64  `json:"size"`
	} `json:"assets"`
}

type goUpdateStatus struct {
	UninstallSupported bool               `json:"uninstallSupported"`
	Manual             bool               `json:"manual"`
	Version            string             `json:"version"`
	Latest             string             `json:"latestVersion,omitempty"`
	ReleaseURL         string             `json:"releaseUrl,omitempty"`
	Available          bool               `json:"available"`
	Dismissed          bool               `json:"dismissed"`
	Checking           bool               `json:"checking"`
	Checked            bool               `json:"checked"`
	CheckedAt          int64              `json:"checkedAt,omitempty"`
	CheckError         string             `json:"checkError,omitempty"`
	ApplySupported     bool               `json:"applySupported"`
	Job                *releaseupdate.Job `json:"job,omitempty"`
}

type goUpdates struct {
	mu        sync.Mutex
	attempted time.Time
	checkedAt time.Time
	latest    string
	ignored   string
	checking  bool
	err       string
}

func newestGoRelease(releases []goRelease) string {
	var latest string
	for _, release := range releases {
		candidate, ok := strings.CutPrefix(release.Tag, "go-")
		if release.Draft || !ok || !releaseupdate.ValidVersion(candidate) {
			continue
		}
		files := map[string]bool{}
		for _, file := range release.Files {
			if file.State == "uploaded" && file.Size > 0 {
				files[file.Name] = true
			}
		}
		prefix := "mxioc-go-" + candidate + "-linux-"
		if files["SHA256SUMS"] && files[prefix+"amd64.tar.gz"] && files[prefix+"arm64.tar.gz"] &&
			version.Compare("go"+candidate[1:], strings.Replace(latest, "v", "go", 1)) > 0 {
			latest = candidate
		}
	}
	return latest
}

func fetchGoRelease(ctx context.Context) (string, error) {
	client := &http.Client{
		Timeout:       8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/"+goReleaseRepo+"/releases?per_page=30", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	response, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", errors.New("release API unavailable")
	}
	const limit = 2 << 20
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	var releases []goRelease
	if err != nil || len(raw) > limit || json.Unmarshal(raw, &releases) != nil || releases == nil {
		return "", errors.New("invalid release API response")
	}
	return newestGoRelease(releases), nil
}

func (u *goUpdates) check(ctx context.Context, now time.Time, fetch func(context.Context) (string, error)) {
	u.mu.Lock()
	if u.checking || (!u.attempted.IsZero() && now.Sub(u.attempted) < 30*time.Second) {
		u.mu.Unlock()
		return
	}
	u.attempted, u.checking = now, true
	u.mu.Unlock()

	latest, err := fetch(ctx)
	u.mu.Lock()
	defer u.mu.Unlock()
	u.checking = false
	if err != nil {
		u.err = "暂时无法读取 GitHub 发布列表，请稍后重试"
		return
	}
	u.err, u.latest, u.checkedAt = "", latest, now
}

func (u *goUpdates) watch(ctx context.Context, interval time.Duration, now func() time.Time, fetch func(context.Context) (string, error)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for ctx.Err() == nil {
		u.check(ctx, now(), fetch)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (u *goUpdates) status(current string) goUpdateStatus {
	u.mu.Lock()
	defer u.mu.Unlock()
	if current == "" {
		current = "dev"
	}
	status := goUpdateStatus{
		Manual: true, Version: current, Latest: u.latest,
		Checking: u.checking, Checked: !u.attempted.IsZero(), CheckError: u.err,
	}
	if !u.checkedAt.IsZero() {
		status.CheckedAt = u.checkedAt.Unix()
	}
	if u.latest != "" {
		status.ReleaseURL = "https://github.com/" + goReleaseRepo + "/releases/tag/go-" + u.latest
		status.Dismissed = u.latest == u.ignored
		status.Available = !status.Dismissed && releaseupdate.Newer(u.latest, current)
	}
	return status
}

func (s *Server) goUpdateRoutes(w http.ResponseWriter, r *http.Request) bool {
	switch {
	case r.URL.Path == "/admin/api/updates" && r.Method == "GET":
	case r.URL.Path == "/admin/api/updates/check" && r.Method == "POST":
		s.updates.check(r.Context(), s.now(), fetchGoRelease)
	case r.URL.Path == "/admin/api/updates/apply" && r.Method == "POST":
		var input struct {
			Version   string `json:"version"`
			Confirmed bool   `json:"confirmed"`
		}
		if err := readJSON(w, r, &input); err != nil || !input.Confirmed || !releaseupdate.ValidVersion(input.Version) {
			problem(w, 400, "请确认要安装的 Go 版本")
			return true
		}
		updater := s.options.ReleaseUpdater
		status := s.updates.status(s.options.Version)
		if updater == nil || !status.Available || status.Latest != input.Version {
			problem(w, 409, "当前安装方式或所选版本暂不可应用，请重新检查")
			return true
		}
		job, err := updater.Start(r.Context(), status.Version, input.Version)
		if err != nil {
			code := 503
			if errors.Is(err, releaseupdate.ErrBusy) {
				code = 409
			}
			problem(w, code, err.Error())
		} else {
			respond(w, http.StatusAccepted, job)
		}
		return true
	case r.URL.Path == "/admin/api/updates/dismiss" && r.Method == "POST":
		var input struct {
			Version string `json:"version"`
		}
		if readJSON(w, r, &input) != nil || !releaseupdate.ValidVersion(input.Version) {
			problem(w, 400, "请选择要忽略的 Go 版本")
			return true
		}
		s.updates.mu.Lock()
		defer s.updates.mu.Unlock()
		if input.Version != s.updates.latest {
			problem(w, 409, "版本信息已变化，请重新检查")
			return true
		}
		s.mu.Lock()
		err := storage.New(s.options.AuthFile).Update(func(doc map[string]any) error {
			doc["goIgnoredRelease"] = input.Version
			return nil
		})
		s.mu.Unlock()
		if err != nil {
			problem(w, 500, "忽略版本保存失败")
		} else {
			s.updates.ignored = input.Version
			respond(w, 200, map[string]any{"ok": true})
		}
		return true
	default:
		return false
	}
	status := s.updates.status(s.options.Version)
	status.UninstallSupported = s.options.ServiceUninstaller != nil
	if updater := s.options.ReleaseUpdater; updater != nil {
		job, err := updater.Status()
		if err == nil {
			status.ApplySupported, status.Job = true, job
		}
	}
	respond(w, 200, status)
	return true
}
