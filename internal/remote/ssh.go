// Package remote implements host-key-pinned native SSH operations.
package remote

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type Connection struct {
	Host, User, Password, Fingerprint string
	PrivateKey                        string
	Port                              int
	AllowLoopback                     bool
}

func (c Connection) address(ctx context.Context) (string, error) {
	if c.Port < 1 || c.Port > 65535 || c.Host == "" {
		return "", errors.New("SSH 地址或端口无效")
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, c.Host)
	if err != nil {
		return "", errors.New("SSH 地址解析失败")
	}
	for _, address := range addresses {
		ip := address.IP
		if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsLoopback() && !c.AllowLoopback {
			continue
		}
		return net.JoinHostPort(ip.String(), strconv.Itoa(c.Port)), nil
	}
	return "", errors.New("SSH 地址不能是回环、链路本地、多播或未指定地址")
}
func preferredHostKeys() []string {
	algorithms := []string{ssh.KeyAlgoED25519}
	for _, algorithm := range ssh.SupportedAlgorithms().HostKeys {
		if algorithm != ssh.KeyAlgoED25519 {
			algorithms = append(algorithms, algorithm)
		}
	}
	return algorithms
}
func handshake(ctx context.Context, c Connection, callback ssh.HostKeyCallback, auth []ssh.AuthMethod, hostKeys ...string) (*ssh.Client, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	address, err := c.address(ctx)
	if err != nil {
		return nil, err
	}
	connection, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, errors.New("SSH 连接失败")
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	done := make(chan struct{})
	watchDone := make(chan struct{})
	defer func() { close(done); <-watchDone }()
	go func() {
		defer close(watchDone)
		select {
		case <-ctx.Done():
			connection.Close()
		case <-done:
		}
	}()
	config := &ssh.ClientConfig{User: c.User, Auth: auth, HostKeyCallback: callback, Timeout: 15 * time.Second}
	if len(hostKeys) == 0 {
		hostKeys = preferredHostKeys()
	}
	config.HostKeyAlgorithms = hostKeys
	transport, channels, requests, err := ssh.NewClientConn(connection, address, config)
	if err != nil {
		connection.Close()
		return nil, err
	}
	_ = connection.SetDeadline(time.Time{})
	return ssh.NewClient(transport, channels, requests), nil
}
func Probe(ctx context.Context, c Connection) (string, error) {
	result := ""
	sentinel := errors.New("host key captured")
	client, err := handshake(ctx, c, func(_ string, _ net.Addr, key ssh.PublicKey) error {
		result = ssh.FingerprintSHA256(key)
		return sentinel
	}, nil)
	if client != nil {
		client.Close()
	}
	if result != "" {
		return result, nil
	}
	if err != nil {
		return "", errors.New("无法获取 SSH 主机指纹")
	}
	return "", errors.New("SSH 主机未返回指纹")
}
func Connect(ctx context.Context, c Connection) (*ssh.Client, error) {
	if c.User == "" || (c.Password == "" && c.PrivateKey == "") || !strings.HasPrefix(c.Fingerprint, "SHA256:") {
		return nil, errors.New("SSH 账号、密码或主机指纹缺失")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	auth := []ssh.AuthMethod{}
	if c.PrivateKey != "" {
		signer, e := ssh.ParsePrivateKey([]byte(c.PrivateKey))
		if e != nil {
			return nil, errors.New("SSH 私钥无效")
		}
		auth = append(auth, ssh.PublicKeys(signer))
	} else {
		auth = append(auth, ssh.Password(c.Password))
	}
	algorithms := preferredHostKeys()
	mismatched := false
	for len(algorithms) > 0 && ctx.Err() == nil {
		keyType := ""
		matched := false
		client, err := handshake(ctx, c, func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if subtle.ConstantTimeCompare([]byte(ssh.FingerprintSHA256(key)), []byte(c.Fingerprint)) != 1 {
				keyType = key.Type()
				return errors.New("host key mismatch")
			}
			matched = true
			return nil
		}, auth, algorithms...)
		if err == nil {
			return client, nil
		}
		if keyType == "" {
			// A matching key followed by an authentication failure is final.
			// Only a callback-rejected key can trigger another negotiation.
			if matched || !mismatched {
				return nil, errors.New("SSH 握手或认证失败，请检查账号、密码和服务器状态")
			}
			break
		}
		mismatched = true
		next := []string{}
		for _, algorithm := range algorithms {
			same := algorithm == keyType
			if keyType == ssh.KeyAlgoRSA {
				same = algorithm == ssh.KeyAlgoRSASHA256 || algorithm == ssh.KeyAlgoRSASHA512
			}
			if keyType == ssh.CertAlgoRSAv01 {
				same = algorithm == ssh.CertAlgoRSASHA256v01 || algorithm == ssh.CertAlgoRSASHA512v01
			}
			if !same {
				next = append(next, algorithm)
			}
		}
		if len(next) == len(algorithms) {
			break
		}
		algorithms = next
	}
	return nil, errors.New("SSH 主机指纹不匹配，已停止连接，请核对服务器后重新检测")
}

type capture struct {
	mu       sync.Mutex
	data     []byte
	limit    int
	overflow bool
}

func (w *capture) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	size := len(p)
	w.data = append(w.data, p...)
	if len(w.data) > w.limit {
		w.data = append([]byte(nil), w.data[len(w.data)-w.limit:]...)
		w.overflow = true
	}
	return size, nil
}
func (w *capture) result() (string, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return string(w.data), w.overflow
}
func quote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }

// Execute uses a fresh SSH connection so cancellation cannot close unrelated
// requests. Secrets travel in the channel input, never in process arguments.
func Execute(ctx context.Context, c Connection, script string, maxOutput int) (string, error) {
	return executeObserved(ctx, c, script, maxOutput, nil)
}

func executeObserved(ctx context.Context, c Connection, script string, maxOutput int, observer io.Writer) (string, error) {
	if _, bounded := ctx.Deadline(); !bounded {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
	}
	if maxOutput < 1 || maxOutput > 16<<20 {
		return "", errors.New("输出大小限制无效")
	}
	client, err := Connect(ctx, c)
	if err != nil {
		return "", err
	}
	defer client.Close()
	return executeClientObserved(ctx, client, c, script, maxOutput, observer)
}

func executeClient(ctx context.Context, client *ssh.Client, c Connection, script string, maxOutput int) (string, error) {
	return executeClientObserved(ctx, client, c, script, maxOutput, nil)
}

type remoteExitError int

func (e remoteExitError) Error() string {
	return "远端命令失败，退出码 " + strconv.Itoa(int(e))
}

func executeClientObserved(ctx context.Context, client *ssh.Client, c Connection, script string, maxOutput int, observer io.Writer) (string, error) {
	if maxOutput < 1 || maxOutput > 16<<20 {
		return "", errors.New("输出大小限制无效")
	}
	session, err := client.NewSession()
	if err != nil {
		return "", errors.New("SSH 会话创建失败")
	}
	defer session.Close()
	command := "bash -s"
	input := script + "\n"
	if c.User != "root" {
		random := make([]byte, 24)
		if _, err = rand.Read(random); err != nil {
			return "", err
		}
		marker := "MXIOC_" + hex.EncodeToString(random)
		// Consume the frame marker whether sudo consumed a password or used a cached
		// / NOPASSWD grant. No password is accidentally interpreted as shell code.
		wrapper := "while IFS= read -r line; do [ \"$line\" = " + quote(marker) + " ] && break; done; exec bash -s"
		command = "sudo -S -p '' sh -c " + quote(wrapper)
		input = c.Password + "\n" + marker + "\n" + script + "\n"
	}
	output := &capture{limit: maxOutput}
	session.Stdout = output
	if observer != nil {
		session.Stdout = io.MultiWriter(output, observer)
	}
	session.Stderr = output
	session.Stdin = strings.NewReader(input)
	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = session.Close()
		_ = client.Close()
		<-done
		return "", errors.New("远端命令超时或已取消，远端进程状态需诊断确认")
	}
	result, overflow := output.result()
	if c.Password != "" {
		result = strings.ReplaceAll(result, c.Password, "[REDACTED]")
	}
	if c.PrivateKey != "" {
		result = strings.ReplaceAll(result, c.PrivateKey, "[REDACTED]")
	}
	if overflow {
		return result, errors.New("远端输出超过读取大小限制")
	}
	if err != nil {
		var status *ssh.ExitError
		if errors.As(err, &status) {
			return result, remoteExitError(status.ExitStatus())
		}
		if errors.Is(err, io.EOF) {
			return result, errors.New("SSH 会话提前断开")
		}
		return result, errors.New("远端命令执行失败")
	}
	return result, nil
}
