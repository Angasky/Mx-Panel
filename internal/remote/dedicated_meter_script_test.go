package remote

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDedicatedMeterScriptIsolatedPreservesCountersAndRejectsDrift(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	write := func(path, body string) {
		if err := os.WriteFile(path, []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(bin, "systemctl"), "#!/bin/sh\nexit 0\n")
	write(filepath.Join(bin, "unshare"), "#!/bin/sh\nshift\nNFT_STATE=$(mktemp -u \"$TEST_ROOT/namespace.XXXXXX\")\nexport NFT_STATE\nexec \"$@\"\n")
	write(filepath.Join(bin, "nft"), `#!/usr/bin/python3
import os,sys,json,re
p=os.environ['NFT_STATE'];args=sys.argv[1:]
try:
 d=json.load(open(p))
except FileNotFoundError:
 d=None
if 'list' in args:
 if d is None:sys.exit(1)
 print('table inet mxioc_usage {')
 for direction in ['up','down']:
  for key in sorted(d['ports']):print('counter '+direction+'_'+key+' { }')
 for chain,direction,field in [('input','up','dport'),('output','down','sport')]:
  print('chain '+chain+' {')
  print('type filter hook '+chain+' priority -10; policy accept;')
  for key in sorted(d['ports']):print('meta l4proto { tcp, udp } th '+field+' '+str(d['ports'][key])+' counter name '+direction+'_'+key)
  print('}')
 print('}');sys.exit(0)
if '-f' not in args:sys.exit(2)
s=open(args[args.index('-f')+1]).read()
if '-c' in args:sys.exit(0)
if 'add table' in s:
 if d is not None:sys.exit(3)
 d={'ports':{},'bytes':{}}
if d is None:sys.exit(4)
for port,key in re.findall(r'th dport (\d+) counter name up_(\d+)',s):
 if key in d['ports']:sys.exit(5)
 d['ports'][key]=int(port);d['bytes'][key]=0
json.dump(d,open(p,'w'))
`)
	live := filepath.Join(root, "live.json")
	run := func(meters Record, id, port int) error {
		script, err := dedicatedMeterScript(meters, id, port)
		if err != nil {
			return err
		}
		script = strings.NewReplacer("/var/lock/mxioc-meter.lock", filepath.Join(root, "lock"), "/etc/mxioc-meter", filepath.Join(root, "meter"), "/etc/systemd/system/mxioc-meter-restore.service", filepath.Join(root, "unit")).Replace(script)
		command := exec.Command("bash", "-c", script)
		command.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "TEST_ROOT="+root, "NFT_STATE="+live)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Log(string(output))
		}
		return err
	}
	if err := run(Record{}, 1, 24001); err != nil {
		t.Fatal(err)
	}
	data := Record{"ports": Record{"1": 24001}, "bytes": Record{"1": 789}}
	raw, _ := json.Marshal(data)
	if err := os.WriteFile(live, raw, 0600); err != nil {
		t.Fatal(err)
	}
	// Response loss before recording meters is retried with the old empty map.
	if err := run(Record{}, 1, 24001); err != nil {
		t.Fatal("retry reset existing target", err)
	}
	if err := run(Record{"1": 24001}, 2, 24002); err != nil {
		t.Fatal(err)
	}
	if err := run(Record{"1": 24001, "2": 24002}, 2, 24002); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(live)
	var current struct {
		Bytes map[string]int `json:"bytes"`
		Ports map[string]int `json:"ports"`
	}
	if json.Unmarshal(raw, &current) != nil || current.Bytes["1"] != 789 || len(current.Ports) != 2 {
		t.Fatal("other counter changed", string(raw))
	}
	current.Ports["1"] = 24999
	raw, _ = json.Marshal(current)
	if err := os.WriteFile(live, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := run(Record{"1": 24001, "2": 24002}, 3, 24003); err == nil {
		t.Fatal("drift overwritten")
	}
}
