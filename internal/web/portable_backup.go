package web

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"

	"github.com/Angasky/dingzhi-ban/internal/backupcrypto"
	"github.com/Angasky/dingzhi-ban/internal/config"
)

func (s *Server) portableBackupRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/backups/portable" {
		return false
	}
	if r.Method != "POST" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	if !s.portableBackupMu.TryLock() {
		problem(w, 429, "另一个备份操作正在处理，请稍后重试")
		return true
	}
	defer s.portableBackupMu.Unlock()
	var in struct {
		Action    string `json:"action"`
		Password  string `json:"password"`
		Archive   string `json:"archive"`
		Revision  string `json:"revision"`
		Confirmed bool   `json:"confirmed"`
	}
	if readJSON(w, r, &in) != nil {
		problem(w, 400, "备份请求无效或超过大小限制")
		return true
	}
	id := r.Header.Get("X-Profile")
	if in.Action == "export" {
		b, e := s.repository.ExportPortable(id, s.now())
		if e != nil {
			problem(w, 400, e.Error())
			return true
		}
		plain, e := json.Marshal(b)
		if e != nil {
			problem(w, 500, "备份生成失败")
			return true
		}
		defer clear(plain)
		encrypted, e := backupcrypto.Encrypt(plain, in.Password)
		if e != nil {
			problem(w, 400, e.Error())
			return true
		}
		respond(w, 200, map[string]any{"archive": base64.StdEncoding.EncodeToString(encrypted), "filename": "mx-panel-subscription-" + s.now().UTC().Format("20060102T150405Z") + ".mxbackup"})
		return true
	}
	if in.Action != "preview" && in.Action != "restore" {
		problem(w, 400, "备份操作无效")
		return true
	}
	if in.Action == "restore" && (!in.Confirmed || in.Revision == "") {
		problem(w, 400, "请先预览并确认覆盖当前订阅 YAML")
		return true
	}
	if len(in.Archive) > base64.StdEncoding.EncodedLen(backupcrypto.MaxArchive) {
		problem(w, 400, "备份文件超过大小限制")
		return true
	}
	encrypted, e := base64.StdEncoding.Strict().DecodeString(in.Archive)
	if e != nil {
		problem(w, 400, "备份文件编码无效")
		return true
	}
	plain, e := backupcrypto.Decrypt(encrypted, in.Password)
	if e != nil {
		problem(w, 400, e.Error())
		return true
	}
	defer clear(plain)
	var b config.PortableBackup
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	if d.Decode(&b) != nil || d.Decode(new(any)) != io.EOF {
		problem(w, 400, "备份内容格式无效")
		return true
	}
	v, e := s.repository.ReviewPortable(id, b, in.Revision, in.Action == "restore")
	if e != nil {
		problem(w, 400, e.Error())
		return true
	}
	respond(w, 200, v)
	return true
}
