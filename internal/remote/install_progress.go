package remote

import (
	"bytes"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Only known stage markers are published while the SSH process is running.
// Raw output can contain credentials. Keep it out of the live event list.
func installStage(line string) string {
	stage, ok := strings.CutPrefix(strings.TrimSuffix(line, "\r"), "MXIOC_STAGE=")
	if ok {
		switch stage {
		case "preflight", "download", "build", "install", "config", "credentials", "service", "installed", "api-check":
			return stage
		}
	}
	return ""
}

type installStageWriter struct {
	line    []byte
	discard bool
	last    string
	report  func(string)
}

func (w *installStageWriter) Write(data []byte) (int, error) {
	n := len(data)
	for len(data) > 0 {
		part, rest, complete := bytes.Cut(data, []byte{'\n'})
		if !w.discard && len(w.line)+len(part) <= 64 {
			w.line = append(w.line, part...)
		} else {
			w.discard = true
		}
		if !complete {
			break
		}
		if !w.discard {
			if stage := installStage(string(w.line)); stage != "" && stage != w.last {
				w.last = stage
				w.report(stage)
			}
		}
		w.line = w.line[:0]
		w.discard = false
		data = rest
	}
	return n, nil
}

func (m *Manager) updateInstallStage(id, stage string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := m.load()
	if err != nil {
		return
	}
	for _, entry := range data["jobs"].([]any) {
		job, ok := entry.(map[string]any)
		if ok && job["id"] == id && job["status"] == "running" && job["stage"] != stage {
			appendInstallStage(job, stage)
			_ = m.flush(data)
			return
		}
	}
}

func appendInstallStage(job Record, stage string) {
	job["stage"] = stage
	history, _ := job["timeline"].([]any)
	if len(history) != 0 {
		last, _ := history[len(history)-1].(Record)
		if last["stage"] == stage {
			return
		}
	}
	if len(history) >= 16 {
		history = history[len(history)-15:]
	}
	job["timeline"] = append(history, Record{"stage": stage, "at": time.Now().Unix()})
}

func installFailure(stage string, code int) string {
	switch stage {
	case "connecting":
		return "SSH 安装会话未就绪，请检查服务器连接、主机指纹和提权权限"
	case "preflight":
		if code == 75 {
			return "远端已有安装任务占用安装锁，请稍后重试"
		}
		return "安装环境检查失败，请检查 root 权限、系统和依赖"
	case "download":
		return "下载安装脚本失败，请检查远端 DNS、网络和下载地址"
	case "build":
		return "计量内核编译或验证失败，请查看下载、内存、磁盘和配置错误；此阶段尚未替换原安装"
	case "install":
		return "安装脚本执行失败，请查看日志中的软件包或安装错误"
	case "config":
		return "内核配置校验或写入失败，请检查配置和文件权限"
	case "credentials":
		return "面板账号配置失败，请检查 x-ui 程序和面板设置"
	case "service":
		return "软件服务启动失败，请检查监听端口和远端服务日志"
	case "api-check":
		return "安装脚本已结束，面板登录或接口验证失败，请查看日志"
	default:
		return "安装结果未确认，请核对远端服务状态"
	}
}

var installTerminalEscape = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
var installSecretLine = regexp.MustCompile(`(?i)(password|passwd|passphrase|username|api[ _-]*token|private[ _-]*key|secret|authorization|用户名|密码|令牌|私钥)["'\s]*[:：=]`)

func redactInstallLog(output string) string {
	lines := strings.Split(strings.ReplaceAll(installTerminalEscape.ReplaceAllString(output, ""), "\r", "\n"), "\n")
	for i, line := range lines {
		if installSecretLine.MatchString(line) {
			lines[i] = "[敏感输出已隐藏]"
		}
	}
	return strings.Join(lines, "\n")
}

// CleanDiagnosticLog shares credential-field and terminal sanitization with
// installation logs, then bounds the result exposed by the diagnostics API.
func CleanDiagnosticLog(output string) string {
	output = strings.ToValidUTF8(redactInstallLog(output), "�")
	if len(output) > 64<<10 {
		output = output[len(output)-(64<<10):]
		for len(output) > 0 && !utf8.RuneStart(output[0]) {
			output = output[1:]
		}
	}
	return output
}
