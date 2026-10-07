package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// procDir copies the proc fixtures into a temporary directory, then applies
// edits: a nil value deletes the file, a string replaces its content.
func procDir(t *testing.T, edits map[string]*string) string {
	t.Helper()
	dir := t.TempDir()
	src := testdata("proc")
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		dst := filepath.Join(dir, rel)
		if info.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	// Deletions first, then writes in path order, so that an edit can
	// replace a file with a directory of the same name.
	rels := make([]string, 0, len(edits))
	for rel := range edits {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	for _, rel := range rels {
		if edits[rel] == nil {
			if err := os.RemoveAll(filepath.Join(dir, rel)); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, rel := range rels {
		content := edits[rel]
		if content == nil {
			continue
		}
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(*content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func str(s string) *string { return &s }

func hostWithProc(t *testing.T, proc string) *Exporter {
	t.Helper()
	cfg := goodHostConfig(t)
	cfg.ProcPath = proc
	return hostExporter(t, cfg)
}

func TestDiskDeviceFilter(t *testing.T) {
	for _, dev := range []string{"sda", "sda8", "sdab12", "vda", "vda1", "xvdb", "hdc3", "nvme0n1", "nvme0n1p2", "mmcblk0", "mmcblk0p1"} {
		if !diskDevice.MatchString(dev) {
			t.Errorf("%s dropped, want kept", dev)
		}
	}
	for _, dev := range []string{"zram0", "loop3", "dm-0", "md127", "sr0", "fd0", "nbd0", "ram1", "nvme0", "mmcblk0boot0", "sda-1", "", "sda\n"} {
		if diskDevice.MatchString(dev) {
			t.Errorf("%q kept, want dropped", dev)
		}
	}
}

func TestDiskKeepsPartitionsAndDropsVirtualDevices(t *testing.T) {
	mfs := collectOnce(t, hostExporter(t, goodHostConfig(t)))
	if successOf(t, mfs, collectorDisk) != 1 {
		t.Fatal("disk collector failed")
	}
	for _, dev := range []string{"sda", "sda1", "sda8"} {
		if _, ok := value(mfs, "node_disk_reads_completed_total", map[string]string{"device": dev}); !ok {
			t.Errorf("%s missing", dev)
		}
	}
	for _, dev := range []string{"loop0", "zram0", "dm-0"} {
		if _, ok := value(mfs, "node_disk_reads_completed_total", map[string]string{"device": dev}); ok {
			t.Errorf("%s emitted", dev)
		}
	}
	// Units: sectors are 512 bytes, times are milliseconds. Discarded
	// sectors stay in sectors, as in node_exporter.
	for _, tt := range []struct {
		name string
		want float64
	}{
		{"node_disk_written_bytes_total", 94000000 * 512},
		{"node_disk_read_bytes_total", 1600000 * 512},
		{"node_disk_write_time_seconds_total", 600},
		{"node_disk_io_time_seconds_total", 320},
		{"node_disk_io_now", 2},
		{"node_disk_discarded_sectors_total", 80000},
		{"node_disk_flush_requests_total", 39000},
		{"node_disk_flush_requests_time_seconds_total", 0.88},
	} {
		if v, _ := value(mfs, tt.name, map[string]string{"device": "sda8"}); v != tt.want {
			t.Errorf("%s{sda8} = %v, want %v", tt.name, v, tt.want)
		}
	}
	if v, _ := value(mfs, "haos_exporter_series_dropped_total", map[string]string{"collector": collectorDisk, "reason": reasonCap}); v != 0 {
		t.Errorf("dropped{disk,cap} = %v, want 0", v)
	}
}

func TestDiskOldKernelEmitsOnlyItsFields(t *testing.T) {
	// A pre-4.18 kernel reports 11 stats (14 fields): no discard or flush.
	proc := procDir(t, map[string]*string{"diskstats": str("   8       0 sda 1 2 3 4 5 6 7 8 9 10 11\n")})
	mfs := collectOnce(t, hostWithProc(t, proc))
	if successOf(t, mfs, collectorDisk) != 1 {
		t.Fatal("disk collector failed")
	}
	if v, _ := value(mfs, "node_disk_io_time_weighted_seconds_total", map[string]string{"device": "sda"}); v != 0.011 {
		t.Errorf("weighted io time = %v, want 0.011", v)
	}
	for _, name := range []string{"node_disk_discards_completed_total", "node_disk_flush_requests_total"} {
		if n := countSeries(mfs, name); n != 0 {
			t.Errorf("%s emitted for a kernel that does not report it", name)
		}
	}
}

func TestDiskDeviceCap(t *testing.T) {
	var b strings.Builder
	for i := range maxDiskDevices + 6 {
		fmt.Fprintf(&b, "   8 %7d sd%s 1 0 8 1 1 0 8 1 0 1 1 0 0 0 0 0 0\n", i, diskName(i))
	}
	proc := procDir(t, map[string]*string{"diskstats": str(b.String())})
	mfs := collectOnce(t, hostWithProc(t, proc))
	if n := countSeries(mfs, "node_disk_reads_completed_total"); n != maxDiskDevices {
		t.Fatalf("%d devices emitted, want %d", n, maxDiskDevices)
	}
	if v, _ := value(mfs, "haos_exporter_series_dropped_total", map[string]string{"collector": collectorDisk, "reason": reasonCap}); v != 6 {
		t.Fatalf("dropped{disk,cap} = %v, want 6", v)
	}
}

// diskName returns the i-th SCSI disk name: a, b, ..., z, aa, ab, ...
func diskName(i int) string {
	name := ""
	for i++; i > 0; i = (i - 1) / 26 {
		name = string(rune('a'+(i-1)%26)) + name
	}
	return name
}

func TestPressure(t *testing.T) {
	mfs := collectOnce(t, hostExporter(t, goodHostConfig(t)))
	if successOf(t, mfs, collectorPressure) != 1 {
		t.Fatal("pressure collector failed")
	}
	for name, want := range map[string]float64{
		"node_pressure_cpu_waiting_seconds_total":    3086.85082,
		"node_pressure_io_waiting_seconds_total":     41.234567,
		"node_pressure_io_stalled_seconds_total":     31.234567,
		"node_pressure_memory_waiting_seconds_total": 2.345678,
		"node_pressure_memory_stalled_seconds_total": 1.234567,
	} {
		if v, ok := value(mfs, name, nil); !ok || v != want {
			t.Errorf("%s = %v (%t), want %v", name, v, ok, want)
		}
	}
	// The fixture has no pressure/irq: skipped, not a failure.
	if n := countSeries(mfs, "node_pressure_irq_stalled_seconds_total"); n != 0 {
		t.Error("irq series emitted without pressure/irq")
	}
	// CPU exports only its "some" line, as node_exporter does.
	if n := countSeries(mfs, "node_pressure_cpu_stalled_seconds_total"); n != 0 {
		t.Error("cpu full line exported")
	}
}

func TestPressureIRQ(t *testing.T) {
	proc := procDir(t, map[string]*string{"pressure/irq": str("full avg10=0.00 avg60=0.00 avg300=0.00 total=5000000\n")})
	mfs := collectOnce(t, hostWithProc(t, proc))
	if v, ok := value(mfs, "node_pressure_irq_stalled_seconds_total", nil); !ok || v != 5 {
		t.Fatalf("irq stalled = %v (%t), want 5", v, ok)
	}
}

func TestPressureUnavailableIsNotAFailure(t *testing.T) {
	proc := procDir(t, map[string]*string{"pressure": nil})
	mfs := collectOnce(t, hostWithProc(t, proc))
	if successOf(t, mfs, collectorPressure) != 1 {
		t.Fatal("a kernel without PSI failed the collector")
	}
	for name := range mfs {
		if strings.HasPrefix(name, "node_pressure_") {
			t.Errorf("%s emitted without /proc/pressure", name)
		}
	}
}

func TestIOCollectorFailuresAreIsolated(t *testing.T) {
	tests := []struct {
		name   string
		edits  map[string]*string
		failed string
		prefix string
	}{
		{"no diskstats", map[string]*string{"diskstats": nil}, collectorDisk, "node_disk_"},
		// A read error other than "not found", as an AppArmor denial would be,
		// must fail the collector rather than read as "no PSI".
		{"unreadable pressure file", map[string]*string{"pressure/io": nil, "pressure/io/x": str("")}, collectorPressure, "node_pressure_"},
		{"io without a full line", map[string]*string{"pressure/io": str("some avg10=0.00 avg60=0.00 avg300=0.00 total=1\n")}, collectorPressure, "node_pressure_"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mfs := collectOnce(t, hostWithProc(t, procDir(t, tt.edits)))
			for _, c := range []string{collectorHost, collectorDisk, collectorPressure} {
				want := 1.0
				if c == tt.failed {
					want = 0
				}
				if got := successOf(t, mfs, c); got != want {
					t.Errorf("%s success = %v, want %v", c, got, want)
				}
			}
			for name := range mfs {
				if strings.HasPrefix(name, tt.prefix) {
					t.Errorf("failed collector emitted %s", name)
				}
			}
			if _, ok := value(mfs, "node_memory_MemTotal_bytes", nil); !ok {
				t.Error("host series missing")
			}
		})
	}
}
