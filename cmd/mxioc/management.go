package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Angasky/dingzhi-ban/deploy"
	"github.com/Angasky/dingzhi-ban/internal/storage"
	"golang.org/x/crypto/acme/autocert"
)

type accessConfig struct {
	Host   string `json:"host"`
	Port   string `json:"port"`
	Email  string `json:"email,omitempty"`
	Domain bool   `json:"domain"`
}

func managementMenu() error {
	if os.Geteuid() != 0 {
		return errors.New("请执行 sudo mx-p")
	}
	if err := managementLogo(); err != nil {
		return err
	}
	c := exec.Command("bash", "-c", deploy.Menu, "mx-p")
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	return c.Run()
}

func resetCredentials(root, auth, username string) error {
	// Reuse bootstrap validation and hashing in an isolated directory. The service
	// must be stopped by the menu so a live session writer cannot race this update.
	tmp, err := os.MkdirTemp("", "mx-p-auth-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err = bootstrap(filepath.Join(tmp, "data"), filepath.Join(tmp, "auth"), username, os.Stdin); err != nil {
		return err
	}
	raw, err := os.ReadFile(filepath.Join(tmp, "auth"))
	if err != nil {
		return err
	}
	var next map[string]any
	if err = json.Unmarshal(raw, &next); err != nil {
		return err
	}
	if info, err := os.Lstat(auth); err != nil || !info.Mode().IsRegular() {
		return errors.New("账号文件不存在或不是普通文件")
	}
	return storage.New(auth).Update(func(doc map[string]any) error {
		for k := range doc {
			delete(doc, k)
		}
		for k, v := range next {
			doc[k] = v
		}
		return nil
	})
}

func gatewayConfig(path string) (accessConfig, error) {
	var c accessConfig
	raw, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err = json.Unmarshal(raw, &c); err != nil {
		return c, err
	}
	port, err := net.LookupPort("tcp", c.Port)
	if err != nil || port < 1 || port > 65535 || port == 62578 {
		return c, errors.New("访问端口无效")
	}
	if c.Domain {
		if c.Port != "443" || !strings.Contains(c.Host, ".") || net.ParseIP(c.Host) != nil {
			return c, errors.New("域名 HTTPS 要求有效域名和 443 端口")
		}
		for _, r := range c.Host {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-') {
				return c, errors.New("域名字符无效")
			}
		}
	} else if net.ParseIP(c.Host) == nil {
		return c, errors.New("IP 模式要求有效 IP 地址")
	}
	return c, nil
}

func selfSignedCertificate(dir, host string) (tls.Certificate, error) {
	certFile, keyFile := filepath.Join(dir, "ip.crt"), filepath.Join(dir, "ip.key")
	if cert, err := tls.LoadX509KeyPair(certFile, keyFile); err == nil {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err == nil && leaf.VerifyHostname(host) == nil && time.Until(leaf.NotAfter) > 24*time.Hour {
			return cert, nil
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0), IPAddresses: []net.IP{net.ParseIP(host)}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})
	if err = os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		return tls.Certificate{}, err
	}
	if err = os.WriteFile(certFile, certPEM, 0600); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

func runGateway(configPath string) error {
	c, err := gatewayConfig(configPath)
	if err != nil {
		return err
	}
	cache := filepath.Join(filepath.Dir(configPath), "certificates")
	if err = os.MkdirAll(cache, 0700); err != nil {
		return err
	}
	target, _ := url.Parse("http://127.0.0.1:62578")
	proxy := &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) {
		r.SetURL(target)
		r.Out.Host = r.In.Host
		r.Out.Header.Del("Forwarded")
		r.Out.Header.Del("X-Forwarded-For")
		r.Out.Header.Del("X-Forwarded-Host")
		r.Out.Header.Del("X-Forwarded-Proto")
		r.SetXForwarded()
		r.Out.Header.Set("X-Forwarded-Proto", "https")
	}}
	service := &http.Server{Addr: net.JoinHostPort("", c.Port), Handler: proxy, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 1 << 20}
	if c.Domain {
		m := &autocert.Manager{Prompt: autocert.AcceptTOS, Email: c.Email, HostPolicy: autocert.HostWhitelist(c.Host), Cache: autocert.DirCache(cache)}
		service.TLSConfig = m.TLSConfig()
		service.TLSConfig.MinVersion = tls.VersionTLS12
		challenge := &http.Server{Addr: ":80", Handler: m.HTTPHandler(nil), ReadHeaderTimeout: 10 * time.Second}
		listener, err := net.Listen("tcp", challenge.Addr)
		if err != nil {
			return fmt.Errorf("证书验证端口 80 不可用: %w", err)
		}
		defer listener.Close()
		go challenge.Serve(listener)
	} else {
		cert, err := selfSignedCertificate(cache, c.Host)
		if err != nil {
			return err
		}
		service.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	return service.ListenAndServeTLS("", "")
}

func checkAccessPorts(path string) error {
	c, err := gatewayConfig(path)
	if err != nil {
		return err
	}
	ports := []string{c.Port}
	if c.Domain {
		ports = append(ports, "80")
	}
	for _, port := range ports {
		l, err := net.Listen("tcp", ":"+port)
		if err != nil {
			return err
		}
		l.Close()
	}
	return nil
}
