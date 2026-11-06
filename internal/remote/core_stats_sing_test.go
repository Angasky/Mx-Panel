package remote

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestSingStatsThroughPinnedSSHForward(t *testing.T) {
	address := singHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.Write(singFrameFixture(singStatFixture("user>>>alice>>>traffic>>>downlink", 73)))
		w.Header().Set("Grpc-Status", "0")
	})
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		socket, err := listener.Accept()
		if err != nil {
			return
		}
		connection, channels, requests, err := ssh.NewServerConn(socket, config)
		if err != nil {
			socket.Close()
			return
		}
		defer connection.Close()
		go ssh.DiscardRequests(requests)
		for incoming := range channels {
			var target struct {
				Host       string
				Port       uint32
				Origin     string
				OriginPort uint32
			}
			if incoming.ChannelType() != "direct-tcpip" || ssh.Unmarshal(incoming.ExtraData(), &target) != nil || net.JoinHostPort(target.Host, value(int(target.Port))) != address {
				incoming.Reject(ssh.Prohibited, "unexpected target")
				continue
			}
			remote, err := net.Dial("tcp", address)
			if err != nil {
				incoming.Reject(ssh.ConnectionFailed, "unavailable")
				continue
			}
			channel, requests, err := incoming.Accept()
			if err != nil {
				remote.Close()
				continue
			}
			go ssh.DiscardRequests(requests)
			go func() {
				defer remote.Close()
				defer channel.Close()
				go func() { io.Copy(remote, channel); remote.Close() }()
				io.Copy(channel, remote)
			}()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Connect(ctx, Connection{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, User: "root", Password: "fixture", Fingerprint: ssh.FingerprintSHA256(signer.PublicKey()), AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for i := 0; i < 2; i++ {
		raw, err := querySingStats(ctx, address, client.DialContext)
		if err != nil {
			t.Fatal("pinned SSH query failed", err)
		}
		counts, err := parseCoreCounters(raw)
		if err != nil || counts["alice"].down != 73 {
			t.Fatal("SSH counters invalid", err)
		}
	}
}

func singStatFixture(name string, value uint64) []byte {
	entry := protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), name)
	entry = protowire.AppendVarint(protowire.AppendTag(entry, 2, protowire.VarintType), value)
	return protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), entry)
}

func singFrameFixture(body []byte) []byte {
	frame := make([]byte, 5)
	binary.BigEndian.PutUint32(frame[1:], uint32(len(body)))
	return append(frame, body...)
}

func singHTTPFixture(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.Config.Protocols = new(http.Protocols)
	server.Config.Protocols.SetUnencryptedHTTP2(true)
	server.Start()
	t.Cleanup(server.Close)
	return server.Listener.Addr().String()
}

func TestSingStatsHTTP2QueryPreservesCountersAndUsesPinnedDial(t *testing.T) {
	response := singFrameFixture(singStatFixture("user>>>alice>>>traffic>>>uplink", 9007199254740993))
	address := singHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.Method != "POST" || r.URL.Path != singStatsMethod || r.Header.Get("TE") != "trailers" {
			t.Error("wrong gRPC request")
		}
		body, _ := io.ReadAll(r.Body)
		want := singFrameFixture(protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), "user>>>"))
		if !bytes.Equal(body, want) {
			t.Error("query changed prefix or reset counters")
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.Write(response)
		w.Header().Set("Grpc-Status", "0")
	})
	dials := 0
	dial := func(ctx context.Context, network, target string) (net.Conn, error) {
		dials++
		if network != "tcp" || target != address {
			t.Error("dial escaped verified loopback address")
		}
		return (&net.Dialer{}).DialContext(ctx, network, target)
	}
	ctx := context.WithValue(context.Background(), coreStatsQueryKey{}, coreStatsQuery(func(ctx context.Context, address string) (string, error) { return querySingStats(ctx, address, dial) }))
	doc := Record{"experimental": Record{"v2ray_api": Record{"listen": address, "stats": Record{"enabled": true}}}}
	for _, binary := range []string{"/usr/local/bin/xray", "go-ssh-grpc"} {
		stats := Record{"listen": address, "binary": binary}
		for i := 0; i < 2; i++ {
			counts, err := queryCoreCounters(ctx, "sing-box", doc, stats, func(context.Context, string, int) (string, error) {
				t.Fatal("query invoked remote shell")
				return "", nil
			})
			if err != nil || counts["alice"].up != 9007199254740993 {
				t.Fatal("inexact or reset counter", err)
			}
		}
	}
	if dials != 4 {
		t.Fatal("query did not use supplied SSH dialer")
	}
	if _, err := queryCoreCounters(context.Background(), "sing-box", doc, Record{"listen": address, "binary": "go-ssh-grpc"}, nil); err == nil {
		t.Fatal("missing SSH query accepted")
	}
	for _, bad := range []string{"example.com:10085", "192.0.2.1:10085", "127.0.0.1:0"} {
		if _, err := querySingStats(ctx, bad, dial); err == nil {
			t.Fatal("non-local query accepted")
		}
	}
	if dials != 4 {
		t.Fatal("invalid endpoint was dialed")
	}
}

func TestSingStatsRejectsFailedAndMalformedReplies(t *testing.T) {
	valid := singFrameFixture(singStatFixture("user>>>alice>>>traffic>>>uplink", 7))
	for _, mode := range []string{"http-error", "redirect", "content-type", "missing-status", "grpc-error", "duplicate-status", "compressed", "truncated", "extra-frame", "oversized", "bad-protobuf"} {
		t.Run(mode, func(t *testing.T) {
			address := singHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/grpc+proto")
				if mode != "missing-status" {
					w.Header().Set("Trailer", "Grpc-Status")
				}
				switch mode {
				case "http-error":
					w.WriteHeader(503)
					return
				case "redirect":
					w.Header().Set("Location", "http://192.0.2.1:10085/")
					w.WriteHeader(307)
					return
				case "content-type":
					w.Header().Set("Content-Type", "text/plain")
				}
				body := append([]byte(nil), valid...)
				switch mode {
				case "compressed":
					body[0] = 1
				case "truncated":
					body = body[:len(body)-1]
				case "extra-frame":
					body = append(body, singFrameFixture(nil)...)
				case "oversized":
					body = make([]byte, (2<<20)+1)
				case "bad-protobuf":
					body = singFrameFixture([]byte{0xff})
				}
				w.Write(body)
				if mode == "grpc-error" {
					w.Header().Set("Grpc-Status", "12")
				} else if mode != "missing-status" {
					w.Header().Set("Grpc-Status", "0")
				}
				if mode == "duplicate-status" {
					w.Header().Add("Grpc-Status", "13")
				}
			})
			if _, err := querySingStats(context.Background(), address, (&net.Dialer{}).DialContext); err == nil {
				t.Fatal("bad reply treated as zero counters")
			}
		})
	}
	address := singHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := querySingStats(ctx, address, (&net.Dialer{}).DialContext); err == nil || time.Since(start) > time.Second {
		t.Fatal("query cancellation did not stop request")
	}
}

func TestSingStatsProtobufValidation(t *testing.T) {
	good := singStatFixture("user>>>alice>>>traffic>>>uplink", 1)
	for _, raw := range [][]byte{
		{0xff}, {0x08, 1}, append(append([]byte(nil), good...), good...),
		singStatFixture("user>>>alice>>>traffic>>>uplink", math.MaxUint64),
		singStatFixture("user>>>alice>>>traffic>>>unknown", 1),
		singStatFixture("other>>>alice>>>traffic>>>uplink", 1),
	} {
		if _, err := singStatsJSON(raw); err == nil {
			t.Fatal("invalid protobuf counter accepted")
		}
	}
	zero := protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), "user>>>alice>>>traffic>>>downlink"))
	json, err := singStatsJSON(zero)
	if err != nil || !strings.Contains(json, `"value":"0"`) {
		t.Fatal("omitted scalar zero rejected", err)
	}
	if _, err := singStatsJSON(nil); err != nil {
		t.Fatal("empty successful response rejected", err)
	}
}
