package collector

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/procfs"
)

type fakeStatFS struct {
	t     *testing.T
	want  string
	stats FSStats
	err   error
}

func (f fakeStatFS) Stat(path string) (FSStats, error) {
	if path != f.want {
		f.t.Errorf("statfs(%q), want %q", path, f.want)
	}
	return f.stats, f.err
}

var fixedNow = func() time.Time { return time.Unix(1767312000, 500000000) }

func hostExporter(t *testing.T, cfg HostConfig) *Exporter {
	t.Helper()
	e, err := New(Config{Host: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func goodHostConfig(t *testing.T) HostConfig {
	return HostConfig{
		ProcPath: testdata("proc"),
		SysPath:  t.TempDir(),
		DataPath: "/data",
		StatFS: fakeStatFS{t: t, want: "/data", stats: FSStats{
			Size:  8000000 * 4096,
			Free:  4000000 * 4096,
			Avail: 3600000 * 4096,
		}},
		Now: fixedNow,
	}
}

func TestHostGolden(t *testing.T) {
	e := hostExporter(t, goodHostConfig(t))
	compareGolden(t, gatherer(t, e, "haos_exporter_collector_duration_seconds"), "host.prom")
}

func TestHostFailureEmitsOnlySuccess(t *testing.T) {
	tests := []struct {
		name string
		cfg  func(HostConfig) HostConfig
	}{
		{"missing proc files", func(c HostConfig) HostConfig { c.ProcPath = t.TempDir(); return c }},
		{"statfs error", func(c HostConfig) HostConfig {
			c.StatFS = fakeStatFS{t: t, want: "/data", err: errors.New("denied")}
			return c
		}},
		{"no mount for the data path", func(c HostConfig) HostConfig {
			c.ProcPath = procWithMountinfo(t, "1001 1000 0:51 / /proc rw,relatime - proc proc rw\n")
			return c
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := hostExporter(t, tt.cfg(goodHostConfig(t)))
			mfs := collectOnce(t, e)
			if successOf(t, mfs, collectorHost) != 0 {
				t.Fatal("host collector reported success")
			}
			// The disk and pressure collectors are separate and may still
			// emit; none of the host collector's own families may.
			for name := range mfs {
				for _, own := range []string{"node_cpu_", "node_memory_", "node_load", "node_filesystem_", "node_boot_time_", "node_time_"} {
					if strings.HasPrefix(name, own) {
						t.Errorf("failed host collector emitted %s", name)
					}
				}
			}
		})
	}
}

// procWithMountinfo copies the proc fixtures into a temporary directory
// with the given self/mountinfo.
func procWithMountinfo(t *testing.T, mountinfo string) string {
	t.Helper()
	dir := t.TempDir()
	for _, f := range []string{"stat", "meminfo", "loadavg"} {
		b, err := os.ReadFile(testdata("proc", f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "self"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "self", "mountinfo"), []byte(mountinfo), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestMountFor(t *testing.T) {
	mounts := []*procfs.MountInfo{
		{MountPoint: "/", Source: "overlay"},
		{MountPoint: "/data", Source: "/dev/sda8"},
		{MountPoint: "/dataset", Source: "wrong-prefix"},
		{MountPoint: "/share", Source: "/dev/sda8"},
		{MountPoint: "/share", Source: "stacked"},
	}
	tests := []struct {
		path, want string
	}{
		{"/data", "/dev/sda8"},
		{"/data/sub/dir", "/dev/sda8"},
		{"/datasets", "overlay"},
		{"/dataset", "wrong-prefix"},
		{"/share", "stacked"},
		{"/tmp", "overlay"},
	}
	for _, tt := range tests {
		m := mountFor(mounts, tt.path)
		if m == nil || m.Source != tt.want {
			t.Errorf("mountFor(%q) = %+v, want source %q", tt.path, m, tt.want)
		}
	}
	if m := mountFor(mounts[1:2], "/tmp"); m != nil {
		t.Errorf("mountFor without / = %+v, want nil", m)
	}
	if m := mountFor(mounts, "relative"); m != nil {
		t.Errorf("mountFor(relative) = %+v, want nil", m)
	}
}
