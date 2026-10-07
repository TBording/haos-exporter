package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.yaml.in/yaml/v2"
	"golang.org/x/crypto/bcrypt"

	"github.com/TBording/haos-exporter/haos_exporter/internal/testcerts"
)

const (
	testToken    = "test-token-not-a-secret"
	testPassword = "scrape-password"
)

// lockedBuffer is a bytes.Buffer safe for the concurrent log writers.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func testHash(t *testing.T) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

// fakeSupervisor serves the app options, a 403 for /addons, and the
// fixtures, with /core/info pointed at a local Core stand-in.
func fakeSupervisor(t *testing.T, options map[string]any) string {
	t.Helper()
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/manifest.json" || r.Header.Get("Authorization") != "" {
			t.Errorf("core probe sent %s with Authorization %q", r.URL.Path, r.Header.Get("Authorization"))
		}
	}))
	t.Cleanup(core.Close)
	cu, _ := url.Parse(core.URL)
	coreHost, corePort, _ := net.SplitHostPort(cu.Host)

	fixtures := map[string]string{
		"/host/info": "host_info.json", "/os/info": "os_info.json", "/core/info": "core_info.json",
		"/supervisor/info": "supervisor_info.json", "/resolution/info": "resolution_info.json",
		"/backups/info": "backups_info.json",
	}
	sup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("Supervisor got %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/addons/self/options/config":
			json.NewEncoder(w).Encode(map[string]any{"result": "ok", "data": options})
			return
		case "/addons":
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("403: Forbidden"))
			return
		}
		name, ok := fixtures[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("404: Not Found"))
			return
		}
		b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "supervisor", name))
		if err != nil {
			t.Error(err)
		}
		if r.URL.Path == "/core/info" {
			var doc map[string]any
			json.Unmarshal(b, &doc)
			data := doc["data"].(map[string]any)
			data["ip_address"] = coreHost
			data["port"], _ = strconv.Atoi(corePort)
			b, _ = json.Marshal(doc)
		}
		w.Write(b)
	}))
	t.Cleanup(sup.Close)
	return sup.URL
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func getenv(name string) string {
	if name == "SUPERVISOR_TOKEN" {
		return testToken
	}
	return ""
}

func TestRunRefusesToStart(t *testing.T) {
	h := testHash(t)
	tests := []struct {
		name    string
		options map[string]any
		extra   []string
		getenv  func(string) string
		want    string
	}{
		{"no password hash", map[string]any{"basic_auth_password_hash": ""}, nil, getenv, "DOCS.md"},
		{"hash not bcrypt", map[string]any{"basic_auth_password_hash": "plain"}, nil, getenv, "not a bcrypt hash"},
		{"bad tls mode", map[string]any{"basic_auth_password_hash": h, "tls_mode": "on"}, nil, getenv, "tls_mode"},
		{"no token", map[string]any{"basic_auth_password_hash": h}, nil, func(string) string { return "" }, "SUPERVISOR_TOKEN"},
		{"user web config", map[string]any{"basic_auth_password_hash": h}, []string{"--web.config.file=/tmp/x.yml"}, getenv, "not supported"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			var stderr lockedBuffer
			args := append([]string{
				"--supervisor.url=" + fakeSupervisor(t, tt.options),
				"--web.config-dir=" + dir,
				"--web.listen-address=" + freeAddr(t),
				"--path.data=" + t.TempDir(),
			}, tt.extra...)
			code := run(context.Background(), args, tt.getenv, &stderr)
			if code == 0 {
				t.Fatalf("run exited 0; log:\n%s", stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.want) {
				t.Fatalf("log does not mention %q:\n%s", tt.want, stderr.String())
			}
			if strings.Contains(stderr.String(), testToken) || strings.Contains(stderr.String(), h) {
				t.Fatalf("log leaks a secret:\n%s", stderr.String())
			}
			if entries, _ := os.ReadDir(dir); len(entries) != 0 {
				t.Fatalf("files written before refusing: %v", entries)
			}
		})
	}
}

func TestRunServesWithBasicAuthAndShutsDown(t *testing.T) {
	for _, mode := range []string{"off", "self_signed"} {
		t.Run(mode, func(t *testing.T) {
			h := testHash(t)
			dir := t.TempDir()
			addr := freeAddr(t)
			var stderr lockedBuffer
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan int, 1)
			go func() {
				done <- run(ctx, []string{
					"--supervisor.url=" + fakeSupervisor(t, map[string]any{
						"basic_auth_username": "prometheus", "basic_auth_password_hash": h,
						"tls_mode": mode, "log_level": "debug", "unknown": true,
					}),
					"--web.config-dir=" + dir,
					"--web.listen-address=" + addr,
					"--path.data=" + t.TempDir(),
				}, getenv, &stderr)
			}()

			deadline := time.Now().Add(10 * time.Second)
			for {
				c, err := net.DialTimeout("tcp", addr, time.Second)
				if err == nil {
					c.Close()
					break
				}
				select {
				case code := <-done:
					t.Fatalf("run exited %d early:\n%s", code, stderr.String())
				default:
				}
				if time.Now().After(deadline) {
					t.Fatalf("server did not come up: %v\n%s", err, stderr.String())
				}
				time.Sleep(50 * time.Millisecond)
			}

			path := filepath.Join(dir, "web-config.yml")
			scheme := "http"
			roots := x509.NewCertPool()
			if mode == "self_signed" {
				scheme = "https"
				// Trust exactly the generated certificate; its SAN must hold
				// the host name from /host/info.
				b, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var wc struct {
					TLS struct {
						Cert string `yaml:"cert"`
					} `yaml:"tls_server_config"`
				}
				if err := yaml.Unmarshal(b, &wc); err != nil {
					t.Fatal(err)
				}
				roots.AppendCertsFromPEM([]byte(wc.TLS.Cert))
			}
			client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "homeassistant"},
			}}
			get := func(auth bool) (*http.Response, error) {
				req, _ := http.NewRequest(http.MethodGet, scheme+"://"+addr+"/metrics", nil)
				if auth {
					req.SetBasicAuth("prometheus", testPassword)
				}
				return client.Do(req)
			}

			resp, err := get(false)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("unauthenticated status %d", resp.StatusCode)
			}
			if (resp.TLS != nil) != (mode == "self_signed") {
				t.Fatalf("TLS state %v for mode %s", resp.TLS != nil, mode)
			}

			resp, err = get(true)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("authenticated status %d:\n%s", resp.StatusCode, body)
			}
			for _, want := range []string{
				`haos_exporter_build_info{`,
				`haos_exporter_security_check{check="role_least_privilege"} 1`,
				`haos_exporter_collector_success{collector="host"} 1`,
				`haos_exporter_collector_success{collector="supervisor_info"} 1`,
				`haos_core_up 1`,
				`node_filesystem_avail_bytes{`,
				`node_uname_info{`,
				`go_goroutines`,
				`process_start_time_seconds`,
			} {
				if !bytes.Contains(body, []byte(want)) {
					t.Errorf("metrics lack %q", want)
				}
			}
			if bytes.Contains(body, []byte("CANARY")) {
				t.Error("metrics contain a secret field")
			}

			st, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if st.Mode().Perm() != 0o600 {
				t.Fatalf("web config mode %v", st.Mode().Perm())
			}

			cancel()
			select {
			case code := <-done:
				if code != 0 {
					t.Fatalf("exit code %d:\n%s", code, stderr.String())
				}
			case <-time.After(10 * time.Second):
				t.Fatal("no shutdown after cancel")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("web config not removed on shutdown: %v", err)
			}
			log := stderr.String()
			for _, secret := range []string{testToken, h, testPassword, "CANARY"} {
				if strings.Contains(log, secret) {
					t.Fatalf("log leaks %q:\n%s", secret, log)
				}
			}
			if !strings.Contains(log, "security check") || !strings.Contains(log, "shutting down") {
				t.Fatalf("expected log lines missing:\n%s", log)
			}
		})
	}
}

func TestHandshakeHangup(t *testing.T) {
	for msg, want := range map[string]bool{
		"http: TLS handshake error from 172.30.32.1:40000: EOF":                                                                          true,
		"http: TLS handshake error from 172.30.32.1:40000: read tcp 172.30.33.2:9100->172.30.32.1:40000: read: connection reset by peer": true,
		"http: TLS handshake error from 172.30.32.1:40000: client sent an HTTP request to an HTTPS server":                               false,
		"http: TLS handshake error from 172.30.32.1:40000: tls: first record does not look like a TLS handshake":                         false,
		"http: TLS handshake error from 172.30.32.1:40000: EOF then more":                                                                false,
		"http: Accept error: accept tcp [::]:9100: EOF":                                                                                  false,
	} {
		if got := handshakeHangup(msg); got != want {
			t.Errorf("handshakeHangup(%q) = %t, want %t", msg, got, want)
		}
	}
}

// TestWatchdogConnectLogsAtDebug connects and closes without a handshake, as
// the Supervisor's watchdog does, and checks that the resulting line is
// logged at debug while other handshake errors stay at warn.
func TestWatchdogConnectLogsAtDebug(t *testing.T) {
	dir := t.TempDir()
	addr := freeAddr(t)
	var stderr lockedBuffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{
			"--supervisor.url=" + fakeSupervisor(t, map[string]any{
				"basic_auth_password_hash": testHash(t), "tls_mode": "self_signed", "log_level": "debug",
			}),
			"--web.config-dir=" + dir,
			"--web.listen-address=" + addr,
			"--path.data=" + t.TempDir(),
		}, getenv, &stderr)
	}()
	waitFor := func(what string, cond func(string) bool) string {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for !cond(stderr.String()) {
			select {
			case code := <-done:
				t.Fatalf("run exited %d early:\n%s", code, stderr.String())
			default:
			}
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s:\n%s", what, stderr.String())
			}
			time.Sleep(20 * time.Millisecond)
		}
		return stderr.String()
	}
	waitFor("the TLS listener", func(s string) bool { return strings.Contains(s, "TLS is enabled") })

	handshakeLines := func(s, suffix string) []string {
		var out []string
		for _, l := range strings.Split(s, "\n") {
			if strings.Contains(l, "TLS handshake error") && strings.Contains(l, suffix) {
				out = append(out, l)
			}
		}
		return out
	}

	// Connect and close, like check_port: one plain close, one reset.
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	c, err = net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c.(*net.TCPConn).SetLinger(0)
	c.Close()
	log := waitFor("two hang-up lines", func(s string) bool {
		return len(handshakeLines(s, ": EOF"))+len(handshakeLines(s, "connection reset by peer")) >= 2
	})
	for _, suffix := range []string{": EOF", "connection reset by peer"} {
		for _, l := range handshakeLines(log, suffix) {
			if !strings.Contains(l, "level=DEBUG") {
				t.Errorf("hang-up not at debug: %s", l)
			}
		}
	}

	// Positive control: plain HTTP to the TLS port is still a warning.
	c, err = net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(c, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
	io.ReadAll(c)
	c.Close()
	log = waitFor("the plain-HTTP line", func(s string) bool {
		return len(handshakeLines(s, "client sent an HTTP request")) > 0
	})
	for _, l := range handshakeLines(log, "client sent an HTTP request") {
		if !strings.Contains(l, "level=WARN") {
			t.Errorf("plain HTTP to the TLS port not at warn: %s", l)
		}
	}

	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("exit code %d:\n%s", code, stderr.String())
	}
}

func TestRunRefusesBadTLSFiles(t *testing.T) {
	h := testHash(t)
	now := time.Now()
	tests := []struct {
		name    string
		options map[string]any
		files   func(t *testing.T, dir string)
		want    string
	}{
		{"provided without files", map[string]any{"basic_auth_password_hash": h, "tls_mode": "provided"},
			func(*testing.T, string) {}, "server key"},
		{"provided with a group-readable key", map[string]any{"basic_auth_password_hash": h, "tls_mode": "provided"},
			func(t *testing.T, dir string) {
				p := testcerts.New(t, testcerts.Server("haos-exporter"))
				testcerts.WriteServer(t, dir, p)
				testcerts.WriteFile(t, filepath.Join(dir, "server.key"), p.KeyPEM, 0o640)
			}, "must not be readable by group or others"},
		{"provided with an expired certificate", map[string]any{"basic_auth_password_hash": h, "tls_mode": "provided"},
			func(t *testing.T, dir string) {
				s := testcerts.Server("haos-exporter")
				s.NotBefore, s.NotAfter = now.Add(-48*time.Hour), now.Add(-time.Hour)
				testcerts.WriteServer(t, dir, testcerts.New(t, s))
			}, "expired"},
		{"client auth without client-ca.crt", map[string]any{"basic_auth_password_hash": h, "tls_client_auth": true},
			func(*testing.T, string) {}, "client-ca.crt"},
		{"client auth with TLS off", map[string]any{"basic_auth_password_hash": h, "tls_mode": "off", "tls_client_auth": true},
			func(*testing.T, string) {}, "tls_client_auth"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsDir, configDir := t.TempDir(), t.TempDir()
			tt.files(t, tlsDir)
			var stderr lockedBuffer
			code := run(context.Background(), []string{
				"--supervisor.url=" + fakeSupervisor(t, tt.options),
				"--web.config-dir=" + configDir,
				"--web.listen-address=" + freeAddr(t),
				"--path.data=" + t.TempDir(),
				"--path.tls=" + tlsDir,
			}, getenv, &stderr)
			if code == 0 {
				t.Fatalf("run exited 0; log:\n%s", stderr.String())
			}
			log := stderr.String()
			if !strings.Contains(log, tt.want) {
				t.Fatalf("log does not mention %q:\n%s", tt.want, log)
			}
			for _, secret := range []string{testToken, h, "PRIVATE KEY-----"} {
				if strings.Contains(log, secret) {
					t.Fatalf("log leaks %q:\n%s", secret, log)
				}
			}
			if entries, _ := os.ReadDir(configDir); len(entries) != 0 {
				t.Fatalf("files written before refusing: %v", entries)
			}
		})
	}
}

// waitUp waits until addr accepts TCP connections, failing if run exits.
func waitUp(t *testing.T, addr string, done <-chan int, stderr *lockedBuffer) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			c.Close()
			return
		}
		select {
		case code := <-done:
			t.Fatalf("run exited %d early:\n%s", code, stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not come up: %v\n%s", err, stderr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestRunProvidedTLSWithClientAuth(t *testing.T) {
	h := testHash(t)
	tlsDir, configDir := t.TempDir(), t.TempDir()
	server := testcerts.New(t, testcerts.Server("haos-exporter"))
	clientA := testcerts.New(t, testcerts.Client("prometheus"))
	clientB := testcerts.New(t, testcerts.Client("prometheus-next"))
	testcerts.WriteServer(t, tlsDir, server)
	testcerts.WriteFile(t, filepath.Join(tlsDir, "client-ca.crt"), clientA.CertPEM, 0o444)

	addr := freeAddr(t)
	var stderr lockedBuffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{
			"--supervisor.url=" + fakeSupervisor(t, map[string]any{
				"basic_auth_password_hash": h, "tls_mode": "provided", "tls_client_auth": true,
			}),
			"--web.config-dir=" + configDir,
			"--web.listen-address=" + addr,
			"--path.data=" + t.TempDir(),
			"--path.tls=" + tlsDir,
		}, getenv, &stderr)
	}()
	waitUp(t, addr, done, &stderr)

	// Each request is a new connection, so file changes apply to it.
	scrape := func(pin *x509.Certificate, serverName string, client *testcerts.Pair) (int, []byte, error) {
		roots := x509.NewCertPool()
		roots.AddCert(pin)
		cfg := &tls.Config{RootCAs: roots, ServerName: serverName}
		if client != nil {
			// Always sent, even when its issuer is not one the server
			// advertises, so the server's chain check is what refuses it.
			cert := client.TLS(t)
			cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }
		}
		c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true, TLSClientConfig: cfg}}
		req, _ := http.NewRequest(http.MethodGet, "https://"+addr+"/metrics", nil)
		req.SetBasicAuth("prometheus", testPassword)
		resp, err := c.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, body, nil
	}

	code, body, err := scrape(server.Cert, "haos-exporter", &clientA)
	if err != nil || code != http.StatusOK {
		t.Fatalf("pinned scrape: %d, %v\n%s", code, err, stderr.String())
	}
	for _, want := range []string{
		`haos_exporter_tls_info{client_auth="true",mode="provided"} 1`,
		`haos_exporter_tls_certificate_expiry_timestamp_seconds{cert="server"}`,
		`haos_exporter_tls_certificate_expiry_timestamp_seconds{cert="client_ca"}`,
		`haos_exporter_collector_success{collector="tls"} 1`,
	} {
		if !bytes.Contains(body, []byte(want)) {
			t.Errorf("metrics lack %q", want)
		}
	}

	// The server's chain check answers a certificate it does not trust with
	// one of these alerts; a missing certificate is "certificate required".
	chainRejected := func(err error) bool {
		return err != nil && (strings.Contains(err.Error(), "unknown certificate authority") || strings.Contains(err.Error(), "bad certificate"))
	}
	if _, _, err := scrape(server.Cert, "haos-exporter", nil); err == nil || !strings.Contains(err.Error(), "certificate required") {
		t.Errorf("no client certificate: err = %v, want certificate required", err)
	}
	if _, _, err := scrape(server.Cert, "haos-exporter", &clientB); !chainRejected(err) {
		t.Errorf("client outside the CA: err = %v, want a chain-verification alert", err)
	}
	impostor := testcerts.New(t, testcerts.Server("haos-exporter"))
	for name, try := range map[string]func() (int, []byte, error){
		"no client certificate":    func() (int, []byte, error) { return scrape(server.Cert, "haos-exporter", nil) },
		"wrong pinned certificate": func() (int, []byte, error) { return scrape(impostor.Cert, "haos-exporter", &clientA) },
		"wrong server_name":        func() (int, []byte, error) { return scrape(server.Cert, "homeassistant", &clientA) },
		"client outside the CA":    func() (int, []byte, error) { return scrape(server.Cert, "haos-exporter", &clientB) },
	} {
		if _, _, err := try(); err == nil {
			t.Errorf("%s: served", name)
		}
	}
	// Plain HTTP, with valid credentials, must not be served: Go's TLS server
	// answers it with a 400.
	plainReq, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/metrics", nil)
	plainReq.SetBasicAuth("prometheus", testPassword)
	plain := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	plainResp, err := plain.Do(plainReq)
	if err != nil {
		t.Fatalf("plain HTTP request failed, so the check proved nothing: %v", err)
	}
	plainBody, _ := io.ReadAll(plainResp.Body)
	plainResp.Body.Close()
	if plainResp.StatusCode != http.StatusBadRequest || bytes.Contains(plainBody, []byte("haos_exporter_")) {
		t.Errorf("plain HTTP: status %d, want 400 without metrics:\n%s", plainResp.StatusCode, plainBody)
	}

	// The web config references the key; it never holds it.
	wc, err := os.ReadFile(filepath.Join(configDir, "web-config.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wc, []byte("PRIVATE KEY")) || !bytes.Contains(wc, []byte("cert_file")) {
		t.Fatalf("web config does not reference the files:\n%s", wc)
	}

	// Client rotation: client-ca.crt now trusts only B.
	testcerts.WriteFile(t, filepath.Join(tlsDir, "client-ca.crt"), clientB.CertPEM, 0o444)
	if code, _, err := scrape(server.Cert, "haos-exporter", &clientB); err != nil || code != http.StatusOK {
		t.Fatalf("rotated client: %d, %v", code, err)
	}
	if _, _, err := scrape(server.Cert, "haos-exporter", &clientA); !chainRejected(err) {
		t.Fatalf("the retired client certificate: err = %v, want a chain-verification alert", err)
	}

	// Server rotation: the new pair is served without a restart.
	next := testcerts.New(t, testcerts.Server("haos-exporter"))
	testcerts.WriteServer(t, tlsDir, next)
	if code, _, err := scrape(next.Cert, "haos-exporter", &clientB); err != nil || code != http.StatusOK {
		t.Fatalf("rotated server: %d, %v", code, err)
	}
	if _, _, err := scrape(server.Cert, "haos-exporter", &clientB); err == nil {
		t.Fatal("the old server certificate was still served")
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit code %d:\n%s", code, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no shutdown after cancel")
	}
	for _, secret := range []string{testToken, h, testPassword, "PRIVATE KEY-----"} {
		if strings.Contains(stderr.String(), secret) {
			t.Fatalf("log leaks %q", secret)
		}
	}
}
