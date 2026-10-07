package collector

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"

	"github.com/TBording/haos-exporter/haos_exporter/internal/sanitize"
)

// dataMountpoint is the host path of the HAOS data partition. Every app's
// /data is a bind mount of a directory on it, and the operator knows the
// filesystem by this name, not by the container path.
const dataMountpoint = "/mnt/data"

// FSStats is the part of statfs(2) the exporter uses, in bytes.
type FSStats struct {
	Size  uint64 // f_blocks × f_frsize
	Free  uint64 // f_bfree × f_frsize
	Avail uint64 // f_bavail × f_frsize: what the Supervisor calls "free"
}

// StatFS reports filesystem usage for a path.
type StatFS interface {
	Stat(path string) (FSStats, error)
}

// HostConfig configures the host collector.
type HostConfig struct {
	// ProcPath is where procfs is mounted, normally /proc.
	ProcPath string
	// SysPath is where sysfs is mounted, normally /sys. The disk collector's
	// library only checks that it exists.
	SysPath string
	// DataPath is the app's data directory, normally /data.
	DataPath string
	// StatFS defaults to statfs(2).
	StatFS StatFS
	// Now defaults to time.Now; it sets node_time_seconds.
	Now func() time.Time
}

var (
	cpuSecondsDesc = prometheus.NewDesc("node_cpu_seconds_total",
		"Seconds the CPUs spent in each mode, from /proc/stat.", []string{"cpu", "mode"}, nil)
	load1Desc = prometheus.NewDesc("node_load1",
		"1m load average, from /proc/loadavg.", nil, nil)
	load5Desc = prometheus.NewDesc("node_load5",
		"5m load average, from /proc/loadavg.", nil, nil)
	load15Desc = prometheus.NewDesc("node_load15",
		"15m load average, from /proc/loadavg.", nil, nil)
	bootTimeDesc = prometheus.NewDesc("node_boot_time_seconds",
		"Host boot time in Unix seconds, from /proc/stat btime.", nil, nil)
	timeDesc = prometheus.NewDesc("node_time_seconds",
		"Wall clock time at scrape, in Unix seconds.", nil, nil)
	fsSizeDesc = prometheus.NewDesc("node_filesystem_size_bytes",
		"Data partition size in bytes (f_blocks × f_frsize).", []string{"device", "fstype", "mountpoint"}, nil)
	fsFreeDesc = prometheus.NewDesc("node_filesystem_free_bytes",
		"Data partition free bytes including root-reserved blocks (f_bfree).", []string{"device", "fstype", "mountpoint"}, nil)
	fsAvailDesc = prometheus.NewDesc("node_filesystem_avail_bytes",
		"Data partition bytes available to unprivileged users (f_bavail); the Supervisor's \"free\".", []string{"device", "fstype", "mountpoint"}, nil)
)

type memField struct {
	desc  *prometheus.Desc
	value func(procfs.Meminfo) *uint64
}

func memDesc(field string) *prometheus.Desc {
	return prometheus.NewDesc("node_memory_"+field+"_bytes",
		"Memory information field "+field+", from /proc/meminfo.", nil, nil)
}

var memFields = []memField{
	{memDesc("MemTotal"), func(m procfs.Meminfo) *uint64 { return m.MemTotalBytes }},
	{memDesc("MemFree"), func(m procfs.Meminfo) *uint64 { return m.MemFreeBytes }},
	{memDesc("MemAvailable"), func(m procfs.Meminfo) *uint64 { return m.MemAvailableBytes }},
	{memDesc("Buffers"), func(m procfs.Meminfo) *uint64 { return m.BuffersBytes }},
	{memDesc("Cached"), func(m procfs.Meminfo) *uint64 { return m.CachedBytes }},
	{memDesc("SwapTotal"), func(m procfs.Meminfo) *uint64 { return m.SwapTotalBytes }},
	{memDesc("SwapFree"), func(m procfs.Meminfo) *uint64 { return m.SwapFreeBytes }},
}

type hostPart struct {
	fs       procfs.FS
	dataPath string
	statfs   StatFS
	now      func() time.Time
}

func newHostPart(cfg HostConfig) (*hostPart, error) {
	fs, err := procfs.NewFS(cfg.ProcPath)
	if err != nil {
		return nil, fmt.Errorf("opening procfs at %s: %w", cfg.ProcPath, err)
	}
	dataPath, err := filepath.Abs(cfg.DataPath)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", cfg.DataPath, err)
	}
	h := &hostPart{fs: fs, dataPath: dataPath, statfs: cfg.StatFS, now: cfg.Now}
	if h.statfs == nil {
		h.statfs = syscallStatFS{}
	}
	if h.now == nil {
		h.now = time.Now
	}
	return h, nil
}

func (*hostPart) name() string { return collectorHost }

func (*hostPart) describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{cpuSecondsDesc, load1Desc, load5Desc, load15Desc,
		bootTimeDesc, timeDesc, fsSizeDesc, fsFreeDesc, fsAvailDesc} {
		ch <- d
	}
	for _, f := range memFields {
		ch <- f.desc
	}
}

func (h *hostPart) update(_ *runState, b *batch) error {
	stat, err := h.fs.Stat()
	if err != nil {
		return fmt.Errorf("reading stat: %w", err)
	}
	for cpu, c := range stat.CPU {
		id := strconv.FormatInt(cpu, 10)
		for _, m := range []struct {
			mode string
			v    float64
		}{
			{"user", c.User}, {"nice", c.Nice}, {"system", c.System}, {"idle", c.Idle},
			{"iowait", c.Iowait}, {"irq", c.IRQ}, {"softirq", c.SoftIRQ}, {"steal", c.Steal},
		} {
			b.add(cpuSecondsDesc, prometheus.CounterValue, m.v, id, m.mode)
		}
	}
	b.gauge(bootTimeDesc, float64(stat.BootTime))

	mem, err := h.fs.Meminfo()
	if err != nil {
		return fmt.Errorf("reading meminfo: %w", err)
	}
	for _, f := range memFields {
		if v := f.value(mem); v != nil {
			b.gauge(f.desc, float64(*v))
		}
	}

	load, err := h.fs.LoadAvg()
	if err != nil {
		return fmt.Errorf("reading loadavg: %w", err)
	}
	b.gauge(load1Desc, load.Load1)
	b.gauge(load5Desc, load.Load5)
	b.gauge(load15Desc, load.Load15)

	mounts, err := h.fs.GetMounts()
	if err != nil {
		return fmt.Errorf("reading mountinfo: %w", err)
	}
	m := mountFor(mounts, h.dataPath)
	if m == nil {
		return fmt.Errorf("no mount contains %s", h.dataPath)
	}
	st, err := h.statfs.Stat(h.dataPath)
	if err != nil {
		return fmt.Errorf("statfs %s: %w", h.dataPath, err)
	}
	device, fstype := sanitize.Label(m.Source), sanitize.Label(m.FSType)
	b.gauge(fsSizeDesc, float64(st.Size), device, fstype, dataMountpoint)
	b.gauge(fsFreeDesc, float64(st.Free), device, fstype, dataMountpoint)
	b.gauge(fsAvailDesc, float64(st.Avail), device, fstype, dataMountpoint)

	b.gauge(timeDesc, float64(h.now().UnixNano())/1e9)
	return nil
}

// mountFor returns the mount that contains path: the entry with the longest
// mount point that is path or a parent of it, the later entry winning a tie
// (it is mounted over the earlier one).
func mountFor(mounts []*procfs.MountInfo, path string) *procfs.MountInfo {
	var best *procfs.MountInfo
	for _, m := range mounts {
		if !within(path, m.MountPoint) {
			continue
		}
		if best == nil || len(m.MountPoint) >= len(best.MountPoint) {
			best = m
		}
	}
	return best
}

func within(path, mountpoint string) bool {
	switch {
	case path == mountpoint:
		return true
	case mountpoint == "/":
		return strings.HasPrefix(path, "/")
	default:
		return strings.HasPrefix(path, mountpoint+"/")
	}
}
