package supervisor

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

// testToken is a fake, low-entropy token.
const testToken = "test-token-not-a-secret"

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "supervisor", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, testToken)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// interleave puts sep between every rune of s.
func interleave(s, sep string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteRune(r)
	}
	return b.String()
}

// TestRedactionBeforeTruncation puts the token across the 200-rune cut. Were
// the message truncated before redaction, a token prefix would survive.
func TestRedactionBeforeTruncation(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(strings.Repeat("x", maxMessageRunes-5) + testToken))
	})
	err := c.Get(context.Background(), PathHostInfo, nil)
	assertCleanError(t, err)
	if msg := err.Error(); strings.Contains(msg, testToken[:5]) {
		t.Fatalf("error keeps a token prefix: %q", msg)
	}
}

func assertCleanError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if strings.Contains(msg, testToken) {
		t.Fatalf("error contains the token: %q", msg)
	}
	if strings.Contains(msg, "http://") || strings.Contains(msg, "https://") {
		t.Fatalf("error contains a URL: %q", msg)
	}
	if strings.Contains(msg, "127.0.0.1") {
		t.Fatalf("error contains the dialled address: %q", msg)
	}
	for e := errors.Unwrap(err); e != nil; e = errors.Unwrap(e) {
		if strings.Contains(e.Error(), testToken) || strings.Contains(e.Error(), "http://") {
			t.Fatalf("wrapped error leaks: %q", e.Error())
		}
	}
}

func TestClientExposesOnlyGet(t *testing.T) {
	typ := reflect.TypeOf(&Client{})
	var names []string
	for i := range typ.NumMethod() {
		names = append(names, typ.Method(i).Name)
	}
	if !reflect.DeepEqual(names, []string{"Get"}) {
		t.Fatalf("Client methods = %v, want only [Get]", names)
	}
}

func TestGetDecodesEnvelopeWithBearerAndGET(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+testToken {
			t.Errorf("Authorization = %q", got)
		}
		if r.URL.Path != PathHostInfo {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(fixture(t, "host_info.json"))
	})
	var info HostInfo
	if err := c.Get(context.Background(), PathHostInfo, &info); err != nil {
		t.Fatal(err)
	}
	if info.Hostname != "homeassistant" || info.Kernel != "6.12.40-haos" || info.DiskLifeTime != nil {
		t.Fatalf("decoded %+v", info)
	}
}

func TestGetNilOutDiscards(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"result":"ok","data":{"anything":1}}`))
	})
	if err := c.Get(context.Background(), "/x", nil); err != nil {
		t.Fatal(err)
	}
}

func TestDecodedStructsNeverHoldSecrets(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write(fixture(t, "supervisor_info.json"))
	})
	var info SupervisorInfo
	if err := c.Get(context.Background(), PathSupervisorInfo, &info); err != nil {
		t.Fatal(err)
	}
	if len(info.Apps) != 4 {
		t.Fatalf("apps = %d", len(info.Apps))
	}
	b, _ := json.Marshal(info)
	if strings.Contains(string(b), "CANARY") {
		t.Fatalf("decoded struct holds a secret field: %s", b)
	}
}

func TestErrors(t *testing.T) {
	tests := []struct {
		name       string
		handler    http.HandlerFunc
		wantIs     error
		wantStatus int
		wantMsg    string
	}{
		{
			name: "plain text 403 from the security middleware",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("403: Forbidden"))
			},
			wantIs:     ErrForbidden,
			wantStatus: 403,
		},
		{
			name: "plain text 404",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte("404: Not Found"))
			},
			wantStatus: 404,
			wantMsg:    "404: Not Found",
		},
		{
			name: "json error envelope",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"result":"error","message":"App example is not running","error_key":"app_not_running_error"}`))
			},
			wantStatus: 400,
			wantMsg:    "App example is not running",
		},
		{
			name: "200 with a non-json body",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Write([]byte("<html>not json</html>"))
			},
			wantStatus: 200,
			wantMsg:    "not a JSON envelope",
		},
		{
			name: "200 with result error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Write([]byte(`{"result":"error","message":"nope"}`))
			},
			wantStatus: 200,
			wantMsg:    "result is not ok: nope",
		},
		{
			name: "data of the wrong shape",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Write([]byte(`{"result":"ok","data":{"hostname":42}}`))
			},
			wantStatus: 200,
			wantMsg:    "decoding data",
		},
		{
			name: "body echoing the token in plain text",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("bad header " + r.Header.Get("Authorization")))
			},
			wantStatus: 500,
			wantMsg:    "[redacted]",
		},
		{
			name: "body echoing the token in json",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{"result": "error", "message": r.Header.Get("Authorization")})
			},
			wantStatus: 401,
			wantMsg:    "[redacted]",
		},
		{
			// Sanitising strips NUL; it must not reassemble the token after
			// redaction has already looked for it.
			name: "body echoing the token interleaved with NUL",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("echo " + interleave(testToken, "\x00")))
			},
			wantStatus: 500,
			wantMsg:    "echo [redacted]",
		},
		{
			name: "body echoing the token interleaved with U+200B",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("echo " + interleave(testToken, "\u200b")))
			},
			wantStatus: 500,
			wantMsg:    "echo [redacted]",
		},
		{
			name: "body echoing the token interleaved with invalid UTF-8",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("echo " + interleave(testToken, "\xff")))
			},
			wantStatus: 500,
			wantMsg:    "echo [redacted]",
		},
		{
			name: "json message echoing the token interleaved with escaped U+200B",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"result":"error","message":"echo ` + interleave(testToken, `\u200b`) + `"}`))
			},
			wantStatus: 400,
			wantMsg:    "echo [redacted]",
		},
		{
			name: "200 result-not-ok echoing the token interleaved with escaped NUL",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Write([]byte(`{"result":"error","message":"echo ` + interleave(testToken, `\u0000`) + `"}`))
			},
			wantStatus: 200,
			wantMsg:    "result is not ok: echo [redacted]",
		},
		{
			name: "redirect is not followed",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != PathHostInfo {
					t.Errorf("redirect followed to %s", r.URL.Path)
				}
				http.Redirect(w, r, "/elsewhere", http.StatusFound)
			},
			wantStatus: 302,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestClient(t, tt.handler)
			var info HostInfo
			err := c.Get(context.Background(), PathHostInfo, &info)
			assertCleanError(t, err)
			var se *Error
			if !errors.As(err, &se) {
				t.Fatalf("error %T is not *Error", err)
			}
			if se.Path != PathHostInfo || se.StatusCode != tt.wantStatus {
				t.Fatalf("Path=%q StatusCode=%d, want %q %d", se.Path, se.StatusCode, PathHostInfo, tt.wantStatus)
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Fatalf("errors.Is(%v, %v) = false", err, tt.wantIs)
			}
			if tt.wantIs == nil && errors.Is(err, ErrForbidden) {
				t.Fatalf("non-403 matched ErrForbidden: %v", err)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.wantMsg)
			}
		})
	}
}

func TestOversizedBodyIsAnError(t *testing.T) {
	// A body of exactly MaxBodyBytes is accepted; one byte more is not.
	pad := func(total int) []byte {
		head := []byte(`{"result":"ok","data":{},"pad":"`)
		tail := []byte(`"}`)
		b := append(head, []byte(strings.Repeat("x", total-len(head)-len(tail)))...)
		return append(b, tail...)
	}
	tests := []struct {
		name    string
		size    int
		wantErr bool
	}{
		{"exactly the cap", MaxBodyBytes, false},
		{"one byte over the cap", MaxBodyBytes + 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := pad(tt.size)
			c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) { w.Write(body) })
			err := c.Get(context.Background(), PathBackupsInfo, &BackupsInfo{})
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			assertCleanError(t, err)
			if !errors.Is(err, ErrBodyTooLarge) {
				t.Fatalf("got %v, want ErrBodyTooLarge", err)
			}
		})
	}
}

func TestTimeout(t *testing.T) {
	release := make(chan struct{})
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		select {
		case <-release:
		case <-time.After(5 * time.Second):
		}
	})
	defer close(release)
	c.timeout = 50 * time.Millisecond
	start := time.Now()
	err := c.Get(context.Background(), PathOSInfo, &OSInfo{})
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Get took %s", elapsed)
	}
	assertCleanError(t, err)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want a deadline error", err)
	}
	if !strings.Contains(err.Error(), PathOSInfo) {
		t.Fatalf("error %q does not name the path", err.Error())
	}
}

func TestConnectionRefused(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	c, err := New("http://"+addr, testToken)
	if err != nil {
		t.Fatal(err)
	}
	err = c.Get(context.Background(), PathCoreInfo, &CoreInfo{})
	assertCleanError(t, err)
	var se *Error
	if !errors.As(err, &se) || se.StatusCode != 0 || se.Path != PathCoreInfo {
		t.Fatalf("got %#v", err)
	}
	if err.Error() != "GET /core/info: connection refused" {
		t.Fatalf("message %q", err.Error())
	}
}

func TestTransportMessageNeverNamesTheAddress(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(172, 30, 32, 2), Port: 80}
	op := func(e error) error {
		return &url.Error{Op: "Get", URL: "http://supervisor/host/info", Err: &net.OpError{Op: "dial", Net: "tcp", Addr: addr, Err: e}}
	}
	tests := []struct {
		err  error
		want string
	}{
		{op(syscall.ECONNREFUSED), "connection refused"},
		{op(syscall.ECONNRESET), "connection closed by the server"},
		{&url.Error{Op: "Get", URL: "http://supervisor/x", Err: &net.DNSError{Err: "no such host", Name: "supervisor", Server: "172.30.32.3:53"}}, "name resolution failed"},
		{&url.Error{Op: "Get", URL: "http://supervisor/x", Err: io.ErrUnexpectedEOF}, "connection closed by the server"},
		{&url.Error{Op: "Get", URL: "http://supervisor/x", Err: tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}}, "TLS handshake failed"},
		{&url.Error{Op: "Get", URL: "http://supervisor/x", Err: context.DeadlineExceeded}, "timed out after 5s"},
		{op(errors.New("something new at 172.30.32.2:80")), "request failed"},
	}
	c := &Client{timeout: DefaultTimeout}
	for _, tt := range tests {
		err := c.transportError("/host/info", tt.err)
		if err.Error() != "GET /host/info: "+tt.want {
			t.Errorf("%v: message %q, want %q", tt.err, err.Error(), tt.want)
		}
		if strings.Contains(err.Error(), "172.30.32") || strings.Contains(err.Error(), "supervisor/") {
			t.Errorf("message leaks the address: %q", err.Error())
		}
	}
}

func TestNewValidates(t *testing.T) {
	tests := []struct {
		url, token string
		ok         bool
	}{
		{"http://supervisor", testToken, true},
		{"http://supervisor/", testToken, true},
		{"https://example.test:8443/base", testToken, true},
		{"http://supervisor", "", false},
		{"ftp://supervisor", testToken, false},
		{"http://user:pass@supervisor", testToken, false},
		{"http://supervisor?x=1", testToken, false},
		{"supervisor", testToken, false},
	}
	for _, tt := range tests {
		_, err := New(tt.url, tt.token)
		if (err == nil) != tt.ok {
			t.Errorf("New(%q) error = %v, want ok=%t", tt.url, err, tt.ok)
		}
		if err != nil && strings.Contains(err.Error(), testToken) {
			t.Errorf("New error leaks the token: %v", err)
		}
	}
}

func TestRelativePathRejected(t *testing.T) {
	c := newTestClient(t, func(http.ResponseWriter, *http.Request) { t.Error("request sent") })
	if err := c.Get(context.Background(), "host/info", nil); err == nil {
		t.Fatal("expected an error")
	}
}
