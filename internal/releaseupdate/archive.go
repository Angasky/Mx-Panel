package releaseupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const assetBase = "https://github.com/" + Repository + "/releases/download/go-"

func releaseClient() *http.Client {
	return &http.Client{Timeout: 3 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		host := req.URL.Host
		if len(via) > 4 || req.URL.Scheme != "https" || req.URL.User != nil ||
			(host != "github.com" && host != "release-assets.githubusercontent.com" && host != "objects.githubusercontent.com") {
			return errors.New("发布包重定向地址无效")
		}
		return nil
	}}
}

func download(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ContentLength > limit {
		return nil, errors.New("发布包不可用或过大")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("发布包读取失败或过大")
	}
	return data, nil
}

func verifyArchive(manifest, data []byte, name string) error {
	count := 0
	for _, line := range strings.Split(string(manifest), "\n") {
		sum, file, ok := strings.Cut(line, "  ")
		if !ok || file != name {
			continue
		}
		count++
		actual := sha256.Sum256(data)
		if hex.EncodeToString(actual[:]) != sum {
			return errors.New("发布包 SHA-256 校验失败")
		}
	}
	if count != 1 {
		return errors.New("发布包缺少唯一的 SHA-256 摘要")
	}
	return nil
}

func extractRelease(data []byte, dir, version, arch string) error {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer gz.Close()
	// Only regular files with exact names may be read. The downloaded
	// installer is discarded in favor of the running release's installer.
	limits := map[string]int64{"mxioc": 40 << 20, "index.html": 4 << 20, "mxioc-go-release.service": 16 << 10,
		"VERSION": 128, "ARCH": 128, "SHA256SUMS": 8 << 10, "install-go.sh": 64 << 10}
	seen := map[string]bool{}
	reader := tar.NewReader(io.LimitReader(gz, 48<<20))
	for {
		h, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		limit := limits[h.Name]
		if h.Typeflag != tar.TypeReg || limit == 0 || h.Size <= 0 || h.Size > limit || seen[h.Name] {
			return errors.New("发布包包含异常文件")
		}
		seen[h.Name] = true
		content, err := io.ReadAll(reader)
		if err != nil {
			return err
		}
		switch h.Name {
		case "install-go.sh":
			continue
		case "VERSION":
			if strings.TrimSpace(string(content)) != version {
				return errors.New("发布包版本不匹配")
			}
		case "ARCH":
			if strings.TrimSpace(string(content)) != arch {
				return errors.New("发布包架构不匹配")
			}
		}
		if err := os.WriteFile(filepath.Join(dir, h.Name), content, 0600); err != nil {
			return err
		}
	}
	if len(seen) != len(limits) {
		return errors.New("发布包缺少必要文件")
	}
	return nil
}
