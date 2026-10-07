package collector

import (
	"context"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func TestCoreProbe(t *testing.T) {
	closedPort := func() int {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}()
	status := func(code int) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }
	}
	tests := []struct {
		name         string
		opts         envOpts
		wantUp       float64
		wantSuccess  float64
		wantRequests []string
	}{
		{"200", envOpts{}, 1, 1, []string{ManifestPath}},
		{"401 is still up", envOpts{core: status(http.StatusUnauthorized)}, 1, 1, []string{ManifestPath}},
		{"404 is still up", envOpts{core: status(http.StatusNotFound)}, 1, 1, []string{ManifestPath}},
		{"500 is still up", envOpts{core: status(http.StatusInternalServerError)}, 1, 1, []string{ManifestPath}},
		{"tls with an unverifiable certificate", envOpts{coreTLS: true}, 1, 1, []string{ManifestPath}},
		{
			name: "redirect to an authenticated path is not followed",
			opts: envOpts{core: func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/api/", http.StatusFound)
			}},
			wantUp: 1, wantSuccess: 1, wantRequests: []string{ManifestPath},
		},
		{
			name: "timeout is down",
			opts: envOpts{probeTimeout: 100 * time.Millisecond, core: func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-r.Context().Done():
				case <-time.After(3 * time.Second):
				}
			}},
			wantUp: 0, wantSuccess: 1, wantRequests: []string{ManifestPath},
		},
		{
			name:   "connection refused is down",
			opts:   envOpts{coreInfo: func(d map[string]any) { d["port"] = closedPort }},
			wantUp: 0, wantSuccess: 1,
		},
		{
			name:        "hostname instead of IP fails the collector",
			opts:        envOpts{coreInfo: func(d map[string]any) { d["ip_address"] = "core.example" }},
			wantSuccess: 0,
		},
		{
			name:        "port out of range fails the collector",
			opts:        envOpts{coreInfo: func(d map[string]any) { d["port"] = 0 }},
			wantSuccess: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, tt.opts)
			mfs := collectOnce(t, e.exporter)
			if got := successOf(t, mfs, collectorCoreProbe); got != tt.wantSuccess {
				t.Fatalf("core_probe success = %v, want %v; logs: %s", got, tt.wantSuccess, e.logs)
			}
			if successOf(t, mfs, collectorCoreInfo) != 1 {
				t.Fatal("core_info failed")
			}
			up, ok := value(mfs, "haos_core_up", nil)
			if tt.wantSuccess == 1 && (!ok || up != tt.wantUp) {
				t.Fatalf("haos_core_up = %v (%t), want %v", up, ok, tt.wantUp)
			}
			if tt.wantSuccess == 0 && ok {
				t.Fatal("haos_core_up emitted by a failed collector")
			}
			if got := e.core.seen(); !reflect.DeepEqual(got, tt.wantRequests) {
				t.Fatalf("Core saw %v, want %v", got, tt.wantRequests)
			}
			for _, a := range e.core.auth {
				if a != "" {
					t.Fatalf("probe sent Authorization %q", a)
				}
			}
		})
	}
}

func TestCoreProbeDirect(t *testing.T) {
	p := NewCoreProbe(time.Second)
	for _, tt := range []struct {
		ip   string
		port int
	}{
		{"", 8123}, {"not-an-ip", 8123}, {"172.30.32.1", -1}, {"172.30.32.1", 65536},
	} {
		if _, err := p.Probe(context.Background(), tt.ip, tt.port, false); err == nil {
			t.Errorf("Probe(%q, %d) accepted", tt.ip, tt.port)
		}
	}
	// IPv6 is bracketed correctly.
	l, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback")
	}
	defer l.Close()
	go http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != ManifestPath {
			t.Errorf("path %s", r.URL.Path)
		}
	}))
	port, _ := strconv.Atoi(func() string { _, p, _ := net.SplitHostPort(l.Addr().String()); return p }())
	up, err := p.Probe(context.Background(), "::1", port, false)
	if err != nil || !up {
		t.Fatalf("IPv6 probe = %t, %v", up, err)
	}
}
