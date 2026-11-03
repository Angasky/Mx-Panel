package remote

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func inboundWriteFixture(t *testing.T) (*Panel, *Record, *int, *string) {
	t.Helper()
	row := Record{"id": 1, "tag": "inbound-24001", "port": 24001, "protocol": "vless", "enable": true, "up": json.Number("9007199254740993"), "down": 0, "total": 0, "expiryTime": 0, "remark": "old", "listen": "", "settings": Record{"clients": []any{Record{"id": "user-id", "email": "fixture", "unknown": "keep"}}, "decryption": "none"}, "streamSettings": Record{"network": "tcp", "security": "none"}, "sniffing": Record{"enabled": true}}
	writes := 0
	mode := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/panel/api/inbounds/list" {
			var obj any = []any{}
			if row != nil {
				obj = []any{row}
			}
			if mode == "malformed" {
				obj = Record{}
			}
			json.NewEncoder(w).Encode(Record{"success": true, "obj": obj})
			return
		}
		writes++
		if mode == "unauthorized" {
			w.WriteHeader(401)
			return
		}
		if mode == "disconnect" {
			c, _, _ := w.(http.Hijacker).Hijack()
			c.Close()
			return
		}
		if strings.Contains(r.URL.Path, "/update/") {
			r.ParseForm()
			if r.Form.Get("up") != "9007199254740993" {
				t.Error("fresh counter lost", r.Form)
			}
			if r.Form.Get("id") != "" || r.Form.Get("tag") != "" {
				t.Error("untrusted id/tag in form")
			}
			for k, values := range r.Form {
				v := values[0]
				switch k {
				case "port", "up", "down", "total", "expiryTime":
					row[k] = json.Number(v)
				case "enable":
					row[k] = v == "true"
				case "settings", "streamSettings", "sniffing":
					doc, err := inboundObject(v)
					if err != nil {
						t.Error(err)
					}
					row[k] = doc
				default:
					row[k] = v
				}
			}
		} else if strings.Contains(r.URL.Path, "/del/") {
			if mode != "not-applied" {
				row = nil
			}
		} else {
			t.Error("unexpected path", r.URL.Path)
		}
		json.NewEncoder(w).Encode(Record{"success": true})
	}))
	t.Cleanup(server.Close)
	base, _ := url.Parse(server.URL + "/")
	return newPanel(base, server.Client().Transport, Record{}, "", "fixture-token", NewPanelSession()), &row, &writes, &mode
}

func TestInboundEditFreshComparePreservesUsersAndCounters(t *testing.T) {
	p, row, writes, _ := inboundWriteFixture(t)
	expected, _ := InboundVersion(*row)
	(*row)["up"] = json.Number("9007199254740993")
	(*row)["down"] = json.Number("55")
	out, err := editPanelInbound(context.Background(), p, Record{}, 1, Record{"remark": "新名称", "enable": false, "id": 999, "tag": "spoof", "up": 1}, expected, func(old, next Record) error { return nil })
	if err != nil || out["updated"] != true || *writes != 1 {
		t.Fatal(out, err, *writes)
	}
	settings := (*row)["settings"].(Record)
	if settings["clients"].([]any)[0].(Record)["unknown"] != "keep" {
		t.Fatal("unknown client fields lost")
	}
	if (*row)["enable"] != false || value((*row)["id"]) != "1" {
		t.Fatal(*row)
	}
}

func TestInboundWriteRejectsStaleTokensAndGuards(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(strconv.FormatBool(remove), func(t *testing.T) {
			p, row, writes, _ := inboundWriteFixture(t)
			expected, _ := InboundVersion(*row)
			(*row)["remark"] = "changed"
			var err error
			if remove {
				_, err = deletePanelInbound(context.Background(), p, Record{}, 1, expected, func(Record) error { t.Fatal("guard before compare"); return nil })
			} else {
				_, err = editPanelInbound(context.Background(), p, Record{}, 1, Record{"enable": false}, expected, func(Record, Record) error { t.Fatal("guard before compare"); return nil })
			}
			if err == nil || *writes != 0 {
				t.Fatal("stale configuration changed", err, *writes)
			}
			expected, _ = InboundVersion(*row)
			_, err = editPanelInbound(context.Background(), p, Record{}, 1, Record{"enable": false}, expected, func(Record, Record) error { return errors.New("owned user removed") })
			if err == nil || *writes != 0 {
				t.Fatal("guard ignored")
			}
		})
	}
}

func TestInboundDeleteConfirmsAbsenceAndNeverReplays(t *testing.T) {
	for _, mode := range []string{"", "not-applied", "unauthorized", "disconnect", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			p, row, writes, behavior := inboundWriteFixture(t)
			expected, _ := InboundVersion(*row)
			*behavior = mode
			guarded := 0
			result, err := deletePanelInbound(context.Background(), p, Record{}, 1, expected, func(Record) error { guarded++; return nil })
			if mode == "" {
				if err != nil || result["deleted"] != true {
					t.Fatal(result, err)
				}
				_, err = deletePanelInbound(context.Background(), p, Record{}, 1, expected, func(Record) error { return nil })
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("unconfirmed deletion reported success")
			}
			want := 1
			if mode == "malformed" {
				want = 0
			}
			if *writes != want {
				t.Fatal("write repeated", *writes)
			}
			if guarded != want {
				t.Fatal("invalid inventory reached guard", guarded)
			}
		})
	}
}

func TestInboundDependencyAndStrictJSON(t *testing.T) {
	p, row, writes, _ := inboundWriteFixture(t)
	expected, _ := InboundVersion(*row)
	registry := Record{"meters": Record{"1": Record{}}}
	_, err := deletePanelInbound(context.Background(), p, registry, 1, expected, func(Record) error { return nil })
	if err == nil || *writes != 0 {
		t.Fatal("orphaned remote meter")
	}
	_, err = editPanelInbound(context.Background(), p, registry, 1, Record{"port": 24002}, expected, func(Record, Record) error { return nil })
	if err == nil || *writes != 0 {
		t.Fatal("changed metered endpoint")
	}
	for _, settings := range []any{`{} {}`, `[]`, Record{"clients": "bad"}} {
		_, _, err = prepareInboundEdit(*row, Record{"settings": settings})
		if err == nil {
			t.Fatal("bad settings accepted", settings)
		}
	}
}

func TestRequestOnceCookie401DoesNotReauthenticateOrReplay(t *testing.T) {
	writes, logins := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/csrf-token":
			json.NewEncoder(w).Encode(Record{"success": true, "obj": "csrf"})
		case "/login":
			logins++
			json.NewEncoder(w).Encode(Record{"success": true})
		default:
			writes++
			w.WriteHeader(401)
		}
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL + "/")
	p := newPanel(base, server.Client().Transport, Record{"connectionMode": "existing"}, "password", "", NewPanelSession())
	_, err := p.RequestOnce(context.Background(), "panel/api/inbounds/del/1", Record{})
	if err == nil || writes != 1 || logins != 1 {
		t.Fatal("mutation replayed", err, writes, logins)
	}
}
