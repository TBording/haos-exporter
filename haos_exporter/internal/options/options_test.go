package options

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/TBording/haos-exporter/haos_exporter/internal/supervisor"
)

// testHash returns a bcrypt hash generated at test time, so no hash is
// committed. Go generates the $2a$ form.
func testHash(t *testing.T) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte("scrape-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func TestValidBcryptHash(t *testing.T) {
	h := testHash(t)
	body := h[4:] // "04$" + 53 characters
	tests := []struct {
		name string
		hash string
		ok   bool
	}{
		{"2a", "$2a$" + body, true},
		{"2b", "$2b$" + body, true},
		{"2y", "$2y$" + body, true},
		{"2x prefix", "$2x$" + body, false},
		{"bare 2", "$2$" + body, false},
		{"argon2", "$argon2id$v=19$m=65536,t=3,p=4$" + body, false},
		{"plain text", "hunter2", false},
		{"truncated", ("$2a$" + body)[:59], false},
		{"extended", "$2a$" + body + "x", false},
		{"cost out of range", "$2a$99" + body[2:], false},
		{"non-numeric cost", "$2a$xx" + body[2:], false},
		{"missing separator", "$2a$04x" + body[3:], false},
		{"character outside the alphabet", "$2a$" + body[:10] + "!" + body[11:], false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		if got := ValidBcryptHash(tt.hash); got != tt.ok {
			t.Errorf("%s: ValidBcryptHash = %t, want %t", tt.name, got, tt.ok)
		}
	}
}

func TestNormalize(t *testing.T) {
	h := testHash(t)
	tests := []struct {
		name    string
		in      Options
		want    Options
		wantErr error
		errText string
	}{
		{
			name: "defaults",
			in:   Options{BasicAuthPasswordHash: h},
			want: Options{BasicAuthUsername: "prometheus", BasicAuthPasswordHash: h, TLSMode: "self_signed", LogLevel: "info"},
		},
		{
			name: "explicit",
			in:   Options{BasicAuthUsername: "scraper", BasicAuthPasswordHash: h, TLSMode: "off", LogLevel: "debug"},
			want: Options{BasicAuthUsername: "scraper", BasicAuthPasswordHash: h, TLSMode: "off", LogLevel: "debug"},
		},
		{name: "no hash", in: Options{}, wantErr: ErrNoPasswordHash},
		{name: "not bcrypt", in: Options{BasicAuthPasswordHash: "plain-password"}, errText: "not a bcrypt hash"},
		{name: "bad tls mode", in: Options{BasicAuthPasswordHash: h, TLSMode: "on"}, errText: "tls_mode"},
		{name: "bad log level", in: Options{BasicAuthPasswordHash: h, LogLevel: "trace"}, errText: "log_level"},
		{name: "colon in username", in: Options{BasicAuthUsername: "a:b", BasicAuthPasswordHash: h}, errText: "basic_auth_username"},
		{name: "control char in username", in: Options{BasicAuthUsername: "a\nb", BasicAuthPasswordHash: h}, errText: "basic_auth_username"},
		{
			name: "provided",
			in:   Options{BasicAuthPasswordHash: h, TLSMode: "provided"},
			want: Options{BasicAuthUsername: "prometheus", BasicAuthPasswordHash: h, TLSMode: "provided", LogLevel: "info"},
		},
		{
			name: "provided with client auth",
			in:   Options{BasicAuthPasswordHash: h, TLSMode: "provided", TLSClientAuth: true},
			want: Options{BasicAuthUsername: "prometheus", BasicAuthPasswordHash: h, TLSMode: "provided", TLSClientAuth: true, LogLevel: "info"},
		},
		{
			name: "self_signed with client auth",
			in:   Options{BasicAuthPasswordHash: h, TLSClientAuth: true},
			want: Options{BasicAuthUsername: "prometheus", BasicAuthPasswordHash: h, TLSMode: "self_signed", TLSClientAuth: true, LogLevel: "info"},
		},
		{name: "client auth without TLS", in: Options{BasicAuthPasswordHash: h, TLSMode: "off", TLSClientAuth: true}, errText: "tls_client_auth"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := tt.in
			err := o.normalize()
			switch {
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
			case tt.errText != "":
				if err == nil || !strings.Contains(err.Error(), tt.errText) {
					t.Fatalf("err = %v, want it to mention %q", err, tt.errText)
				}
			default:
				if err != nil {
					t.Fatal(err)
				}
				if o != tt.want {
					t.Fatalf("got %+v, want %+v", o, tt.want)
				}
			}
			if err != nil && tt.in.BasicAuthPasswordHash != "" && strings.Contains(err.Error(), tt.in.BasicAuthPasswordHash) {
				t.Fatalf("error leaks the hash: %v", err)
			}
		})
	}
}

func TestOptionsNeverPrintTheHash(t *testing.T) {
	o := Options{BasicAuthUsername: "prometheus", BasicAuthPasswordHash: testHash(t), TLSMode: "off", LogLevel: "info"}
	var buf strings.Builder
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "options", o)
	for _, s := range []string{o.String(), fmt.Sprintf("%v", o), fmt.Sprintf("%+v", o), buf.String()} {
		if strings.Contains(s, o.BasicAuthPasswordHash) || strings.Contains(s, "$2a$") {
			t.Fatalf("hash printed: %s", s)
		}
	}
}

func TestFromSupervisor(t *testing.T) {
	h := testHash(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != supervisor.PathSelfOptions {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		fmt.Fprintf(w, `{"result":"ok","data":{"basic_auth_username":"scraper","basic_auth_password_hash":%q,"tls_mode":"off","log_level":"warn","unknown_key":[1,2]}}`, h)
	}))
	defer srv.Close()
	c, err := supervisor.New(srv.URL, "test-token-not-a-secret")
	if err != nil {
		t.Fatal(err)
	}
	o, err := FromSupervisor(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	want := Options{BasicAuthUsername: "scraper", BasicAuthPasswordHash: h, TLSMode: "off", LogLevel: "warn"}
	if o != want {
		t.Fatalf("got %+v", o)
	}
}

func TestFromSupervisorMissingHash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"result":"ok","data":{"basic_auth_username":"prometheus","basic_auth_password_hash":"","tls_mode":"self_signed","log_level":"info"}}`))
	}))
	defer srv.Close()
	c, _ := supervisor.New(srv.URL, "test-token-not-a-secret")
	if _, err := FromSupervisor(context.Background(), c); !errors.Is(err, ErrNoPasswordHash) {
		t.Fatalf("err = %v", err)
	}
}

func TestFromFile(t *testing.T) {
	h := testHash(t)
	dir := t.TempDir()
	good := filepath.Join(dir, "options.json")
	os.WriteFile(good, []byte(fmt.Sprintf(`{"basic_auth_password_hash":%q}`, h)), 0o600)
	o, err := FromFile(good)
	if err != nil {
		t.Fatal(err)
	}
	if o.BasicAuthUsername != "prometheus" || o.TLSMode != "self_signed" {
		t.Fatalf("%+v", o)
	}

	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`not json`), 0o600)
	if _, err := FromFile(bad); err == nil {
		t.Fatal("bad JSON accepted")
	}
	big := filepath.Join(dir, "big.json")
	os.WriteFile(big, []byte(`{"x":"`+strings.Repeat("a", maxFileBytes)+`"}`), 0o600)
	if _, err := FromFile(big); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized file: %v", err)
	}
	if _, err := FromFile(filepath.Join(dir, "absent.json")); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestParseLogLevel(t *testing.T) {
	for in, want := range map[string]slog.Level{"debug": slog.LevelDebug, "info": slog.LevelInfo, "warn": slog.LevelWarn, "error": slog.LevelError} {
		if got, err := ParseLogLevel(in); err != nil || got != want {
			t.Errorf("ParseLogLevel(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseLogLevel("warning"); err == nil {
		t.Error("warning accepted")
	}
}

// Options saved by 0.3.x have no tls_client_auth key.
func TestFromSupervisorWithoutClientAuthKey(t *testing.T) {
	h := testHash(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"result":"ok","data":{"basic_auth_username":"prometheus","basic_auth_password_hash":%q,"tls_mode":"self_signed","log_level":"info"}}`, h)
	}))
	defer srv.Close()
	c, err := supervisor.New(srv.URL, "token")
	if err != nil {
		t.Fatal(err)
	}
	o, err := FromSupervisor(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if o.TLSClientAuth || o.TLSMode != TLSSelfSigned {
		t.Fatalf("got %+v, want self_signed without client auth", o)
	}
}

func TestOptionsPrintClientAuth(t *testing.T) {
	o := Options{TLSMode: TLSProvided, TLSClientAuth: true}
	if !strings.Contains(o.String(), "tls_client_auth=true") {
		t.Fatalf("String() = %s", o.String())
	}
	var buf strings.Builder
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "options", o)
	if !strings.Contains(buf.String(), "tls_client_auth=true") {
		t.Fatalf("LogValue = %s", buf.String())
	}
}
