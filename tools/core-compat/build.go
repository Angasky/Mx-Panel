// Build pinned compatibility cores locally, without installing them.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type Spec struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	File     string `json:"file"`
	Original string `json:"originalSHA256"`
	Patched  string `json:"patchedSHA256"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func digest(path string) string {
	b, e := os.ReadFile(path)
	must(e)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func command(dir string, env []string, name string, args ...string) {
	c := exec.Command(name, args...)
	c.Dir = dir
	c.Env = env
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	must(c.Run())
}
func main() {
	goBin := flag.String("go", "go", "Go executable")
	output := flag.String("output", "", "output directory")
	arch := flag.String("arch", "amd64", "amd64 or arm64")
	source := flag.String("source", "tools/core-compat", "patch and manifest directory")
	flag.Parse()
	if *output == "" || (*arch != "amd64" && *arch != "arm64") {
		panic("--output and valid --arch required")
	}
	executable, e := exec.LookPath(*goBin)
	must(e)
	executable, e = filepath.Abs(executable)
	must(e)
	base, e := filepath.Abs(*source)
	must(e)
	out, e := filepath.Abs(*output)
	must(e)
	must(os.MkdirAll(out, 0700))
	raw, e := os.ReadFile(filepath.Join(base, "manifest.json"))
	must(e)
	var specs map[string]Spec
	must(json.Unmarshal(raw, &specs))
	results := map[string]any{}
	for _, name := range []string{"sing-box", "mihomo"} {
		spec := specs[name]
		func() {
			tmp, e := os.MkdirTemp("", "mxioc-core-build-")
			must(e)
			defer os.RemoveAll(tmp)
			c := exec.Command(executable, "mod", "download", "-json", spec.Module+"@"+spec.Version)
			c.Dir = tmp
			c.Stderr = os.Stderr
			metadata, e := c.Output()
			must(e)
			var module struct{ Dir, Sum string }
			must(json.Unmarshal(metadata, &module))
			target := filepath.Join(tmp, "source")
			command(tmp, os.Environ(), "cp", "-R", module.Dir, target)
			file := filepath.Join(target, spec.File)
			if digest(file) != spec.Original {
				panic("source digest mismatch")
			}
			must(os.Chmod(file, 0600))
			command(target, os.Environ(), "patch", "--batch", "--forward", "-p1", "-i", filepath.Join(base, name+".patch"))
			if digest(file) != spec.Patched {
				panic("patched digest mismatch")
			}
			binary := name + "-" + spec.Version[1:] + "-compat-linux-" + *arch
			args := []string{"build", "-trimpath", "-ldflags=-s -w", "-o", filepath.Join(out, binary)}
			if name == "sing-box" {
				args = append(args, "-tags", "with_quic,with_utls,with_v2ray_api", "./cmd/sing-box")
			} else {
				args = append(args, ".")
			}
			env := append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+*arch)
			command(target, env, executable, args...)
			license, e := os.ReadFile(filepath.Join(module.Dir, "LICENSE"))
			must(e)
			must(os.WriteFile(filepath.Join(out, name+"-LICENSE"), license, 0600))
			results[name] = map[string]any{"source": spec, "moduleSum": module.Sum, "binary": binary, "binarySHA256": digest(filepath.Join(out, binary))}
		}()
	}
	encoded, e := json.MarshalIndent(results, "", "  ")
	must(e)
	must(os.WriteFile(filepath.Join(out, "manifest-"+*arch+".json"), append(encoded, '\n'), 0600))
	fmt.Println(out)
}
