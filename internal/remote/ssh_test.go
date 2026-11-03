package remote

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func sshFixture(t *testing.T, extra ...ssh.Signer) (Connection, *atomic.Int32) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	var authCalls atomic.Int32
	config := &ssh.ServerConfig{PasswordCallback: func(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		authCalls.Add(1)
		if metadata.User() != "root" || string(password) != "ssh-test-password" {
			return nil, errors.New("bad auth")
		}
		return nil, nil
	}}
	config.AddHostKey(signer)
	for _, key := range extra {
		config.AddHostKey(key)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			socket, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer socket.Close()
				connection, channels, requests, err := ssh.NewServerConn(socket, config)
				if err != nil {
					return
				}
				defer connection.Close()
				go ssh.DiscardRequests(requests)
				for incoming := range channels {
					if incoming.ChannelType() != "session" {
						incoming.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					channel, requests, err := incoming.Accept()
					if err != nil {
						return
					}
					go func() {
						defer channel.Close()
						for request := range requests {
							if request.Type != "exec" {
								request.Reply(false, nil)
								continue
							}
							request.Reply(true, nil)
							input, _ := io.ReadAll(channel)
							if strings.Contains(string(input), "wait-until-cancelled") {
								io.Copy(io.Discard, channel)
								return
							}
							io.WriteString(channel, "SSH proof ssh-test-password\n")
							channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
							return
						}
					}()
				}
			}()
		}
	}()
	address := listener.Addr().(*net.TCPAddr)
	return Connection{Host: "127.0.0.1", Port: address.Port, User: "root", Password: "ssh-test-password", Fingerprint: ssh.FingerprintSHA256(signer.PublicKey()), AllowLoopback: true}, &authCalls
}
func TestPinnedSSHProbeAuthenticationAndCommand(t *testing.T) {
	c, calls := sshFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pin, err := Probe(ctx, c)
	if err != nil || pin != c.Fingerprint {
		t.Fatal("probe failed", err)
	}
	if calls.Load() != 0 {
		t.Fatal("probe attempted password auth")
	}
	wrong := c
	wrong.Fingerprint = "SHA256:" + strings.Repeat("A", 43)
	if _, err = Connect(ctx, wrong); err == nil {
		t.Fatal("changed host key accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("password sent before pin match")
	}
	client, err := Connect(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = client.SendRequest("keepalive@test", false, nil); err != nil {
		t.Fatal("handshake context closed established connection", err)
	}
	client.Close()
	result, err := Execute(ctx, c, "printf proof", 1024)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result, "SSH proof [REDACTED]") || strings.Contains(result, c.Password) {
		t.Fatal("command output or redaction failed")
	}
	if _, err = Execute(ctx, c, "printf proof", 5); err == nil {
		t.Fatal("oversized output accepted")
	}
	wrong = c
	wrong.Password = "wrong-password"
	if _, err = Connect(ctx, wrong); err == nil {
		t.Fatal("wrong password accepted")
	}
	blocked := c
	blocked.AllowLoopback = false
	if _, err = Connect(ctx, blocked); err == nil {
		t.Fatal("production loopback target accepted")
	}
}
