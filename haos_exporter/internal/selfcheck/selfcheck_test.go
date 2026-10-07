package selfcheck

import (
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/TBording/haos-exporter/haos_exporter/internal/supervisor"
)

// fakeProc builds a procfs tree with self -> 4242 and the given status and
// AppArmor attr files. An empty attr value leaves the file out.
func fakeProc(t *testing.T, capEff, attrCurrent, attrAppArmor string) string {
	t.Helper()
	dir := t.TempDir()
	pid := filepath.Join(dir, "4242")
	if err := os.MkdirAll(filepath.Join(pid, "attr", "apparmor"), 0o755); err != nil {
		t.Fatal(err)
	}
	status := "Name:\thaos-exporter\nUid:\t65532\t65532\t65532\t65532\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t" + capEff + "\nCapBnd:\t00000000a80425fb\n"
	if err := os.WriteFile(filepath.Join(pid, "status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
	if attrCurrent != "" {
		if err := os.WriteFile(filepath.Join(pid, "attr", "current"), []byte(attrCurrent), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if attrAppArmor != "" {
		if err := os.WriteFile(filepath.Join(pid, "attr", "apparmor", "current"), []byte(attrAppArmor), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("4242", filepath.Join(dir, "self")); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestNonroot(t *testing.T) {
	for uid, want := range map[int]bool{0: false, 65532: true, 1000: true} {
		r := nonroot(Config{Geteuid: func() int { return uid }})
		if r.Passed != want || r.Check != CheckNonroot {
			t.Errorf("uid %d: %+v", uid, r)
		}
	}
}

func TestNoCapabilities(t *testing.T) {
	tests := []struct {
		capEff string
		want   bool
	}{
		{"0000000000000000", true},
		{"00000000a80425fb", false},
		{"0000000000000400", false},
	}
	for _, tt := range tests {
		r := noCapabilities(Config{ProcPath: fakeProc(t, tt.capEff, "", "")})
		if r.Passed != tt.want {
			t.Errorf("CapEff %s: %+v", tt.capEff, r)
		}
	}
	if r := noCapabilities(Config{ProcPath: t.TempDir()}); r.Passed {
		t.Errorf("missing /proc/self passed: %+v", r)
	}
}

func TestAppArmorEnforced(t *testing.T) {
	tests := []struct {
		name, current, apparmor string
		want                    bool
		wantLabel               string
	}{
		{"enforce", "local_haos_exporter (enforce)\n", "", true, "local_haos_exporter (enforce)"},
		{"enforce with NUL", "local_haos_exporter (enforce)\x00", "", true, "local_haos_exporter (enforce)"},
		{"complain", "local_haos_exporter (complain)\n", "", false, "(complain)"},
		{"unconfined", "unconfined\n", "", false, "unconfined"},
		{"docker-default also counts as enforce", "docker-default (enforce)\n", "", true, "docker-default"},
		{"apparmor-specific file wins", "unconfined\n", "local_haos_exporter (enforce)\n", true, "local_haos_exporter"},
		{"apparmor-specific complain wins", "x (enforce)\n", "local_haos_exporter (complain)\n", false, "complain"},
		{"no files", "", "", false, "no AppArmor label"},
		{"bare suffix", "(enforce)\n", "", false, "(enforce)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := appArmorEnforced(Config{ProcPath: fakeProc(t, "0000000000000000", tt.current, tt.apparmor)})
			if r.Passed != tt.want || !strings.Contains(r.Detail, tt.wantLabel) {
				t.Fatalf("%+v", r)
			}
		})
	}
}

func TestAppArmorBlocksWrite(t *testing.T) {
	t.Run("write succeeds: fails and cleans up", func(t *testing.T) {
		dir := t.TempDir()
		r := appArmorBlocksWrite(Config{ShmPath: dir, CreateTemp: os.CreateTemp})
		if r.Passed {
			t.Fatalf("%+v", r)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("probe file left behind: %v", entries)
		}
	})
	for _, errno := range []syscall.Errno{syscall.EACCES, syscall.EPERM} {
		t.Run("permission error "+errno.Error()+": passes", func(t *testing.T) {
			deny := func(dir, pattern string) (*os.File, error) {
				return nil, &fs.PathError{Op: "open", Path: filepath.Join(dir, pattern), Err: errno}
			}
			r := appArmorBlocksWrite(Config{ShmPath: "/dev/shm", CreateTemp: deny})
			if !r.Passed || !strings.Contains(r.Detail, "refused") {
				t.Fatalf("%+v", r)
			}
		})
	}
	t.Run("missing directory (ENOENT): fails and names the errno", func(t *testing.T) {
		r := appArmorBlocksWrite(Config{ShmPath: filepath.Join(t.TempDir(), "absent"), CreateTemp: os.CreateTemp})
		if r.Passed || !strings.Contains(r.Detail, "errno 2") || !strings.Contains(r.Detail, "no such file") {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("other errno (EROFS): fails and names the errno", func(t *testing.T) {
		rofs := func(dir, pattern string) (*os.File, error) {
			return nil, &fs.PathError{Op: "open", Path: filepath.Join(dir, pattern), Err: syscall.EROFS}
		}
		r := appArmorBlocksWrite(Config{ShmPath: "/dev/shm", CreateTemp: rofs})
		if r.Passed || !strings.Contains(r.Detail, fmt.Sprintf("errno %d", int(syscall.EROFS))) {
			t.Fatalf("%+v", r)
		}
	})
}

func TestRoleLeastPrivilege(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    bool
	}{
		{"403 passes", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("403: Forbidden"))
		}, true},
		{"200 fails", func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte(`{"result":"ok","data":{"addons":[]}}`))
		}, false},
		{"401 fails", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("401: Unauthorized"))
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var paths []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				paths = append(paths, r.Method+" "+r.URL.Path)
				tt.handler(w, r)
			}))
			defer srv.Close()
			c, err := supervisor.New(srv.URL, "test-token-not-a-secret")
			if err != nil {
				t.Fatal(err)
			}
			r := roleLeastPrivilege(context.Background(), Config{Supervisor: c})
			if r.Passed != tt.want {
				t.Fatalf("%+v", r)
			}
			if len(paths) != 1 || paths[0] != "GET /addons" {
				t.Fatalf("requests %v", paths)
			}
		})
	}
}

type errGetter struct{ err error }

func (g errGetter) Get(context.Context, string, any) error { return g.err }

func TestRunAndMetric(t *testing.T) {
	proc := fakeProc(t, "0000000000000000", "local_haos_exporter (enforce)\n", "")
	results := Run(context.Background(), Config{
		ProcPath:   proc,
		ShmPath:    "/dev/shm",
		Geteuid:    func() int { return 65532 },
		CreateTemp: func(string, string) (*os.File, error) { return nil, fs.ErrPermission },
		Supervisor: errGetter{&supervisor.Error{}},
	})
	var got []string
	for _, r := range results {
		got = append(got, r.Check)
	}
	want := []string{CheckNonroot, CheckNoCapabilities, CheckAppArmorEnforced, CheckAppArmorBlocksWrite, CheckRoleLeastPrivilege}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("checks %v", got)
	}
	expected := `
# HELP haos_exporter_security_check Start-up security self-check: 1 if the check passed (the container is confined as intended), 0 if not.
# TYPE haos_exporter_security_check gauge
haos_exporter_security_check{check="apparmor_blocks_write"} 1
haos_exporter_security_check{check="apparmor_enforced"} 1
haos_exporter_security_check{check="no_capabilities"} 1
haos_exporter_security_check{check="nonroot"} 1
haos_exporter_security_check{check="role_least_privilege"} 0
`
	if err := testutil.CollectAndCompare(Metric(results), strings.NewReader(expected)); err != nil {
		t.Fatal(err)
	}
}
