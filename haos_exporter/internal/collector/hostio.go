package collector

import (
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
	"github.com/prometheus/procfs/blockdevice"
)

// Disk IO and pressure stall information, in node_exporter's names and
// units (collector/diskstats_* and collector/pressure_linux.go at v1.12.1).
// /proc/diskstats and /proc/pressure/* are kernel-global, so an app without
// host_pid reads the host's values. Each is its own collector, so a missing
// or unreadable file costs only its own series.

// diskDevice keeps whole disks and their partitions. It deliberately differs
// from node_exporter's default filter, which drops partitions: per-partition
// IO (the data partition against the rest of the disk) is what the guest can
// see and the hypervisor cannot. zram, loop, device-mapper and md devices are
// left out. A match also guarantees a label-safe value.
var diskDevice = regexp.MustCompile(`^(?:(?:[hsv]|xv)d[a-z]+\d*|nvme\d+n\d+(?:p\d+)?|mmcblk\d+(?:p\d+)?)$`)

const (
	maxDiskDevices = 64
	// /proc/diskstats counts 512-byte sectors whatever the device's block
	// size, and times in milliseconds.
	diskSectorBytes = 512.0
	diskTickSeconds = 1.0 / 1000.0
)

type diskStat struct {
	desc  *prometheus.Desc
	vt    prometheus.ValueType
	value func(blockdevice.IOStats) float64
}

func diskDesc(name, help string) *prometheus.Desc {
	return prometheus.NewDesc("node_disk_"+name, help+" From /proc/diskstats.", []string{"device"}, nil)
}

// diskStats is in /proc/diskstats field order. A kernel that reports fewer
// fields (no discard counters before 4.18, no flush counters before 5.5)
// emits a prefix of the list.
var diskStats = []diskStat{
	{diskDesc("reads_completed_total", "The total number of reads completed successfully."), prometheus.CounterValue,
		func(s blockdevice.IOStats) float64 { return float64(s.ReadIOs) }},
	{diskDesc("reads_merged_total", "The total number of reads merged."), prometheus.CounterValue,
		func(s blockdevice.IOStats) float64 { return float64(s.ReadMerges) }},
	{diskDesc("read_bytes_total", "The total number of bytes read successfully."), prometheus.CounterValue,
		func(s blockdevice.IOStats) float64 { return float64(s.ReadSectors) * diskSectorBytes }},
	{diskDesc("read_time_seconds_total", "The total number of seconds spent by all reads."), prometheus.CounterValue,
		func(s blockdevice.IOStats) float64 { return float64(s.ReadTicks) * diskTickSeconds }},
	{diskDesc("writes_completed_total", "The total number of writes completed successfully."), prometheus.CounterValue,
		func(s blockdevice.IOStats) float64 { return float64(s.WriteIOs) }},
	{diskDesc("writes_merged_total", "The number of writes merged."), prometheus.CounterValue,
		func(s blockdevice.IOStats) float64 { return float64(s.WriteMerges) }},
	{diskDesc("written_bytes_total", "The total number of bytes written successfully."), prometheus.CounterValue,
		func(s blockdevice.IOStats) float64 { return float64(s.WriteSectors) * diskSectorBytes }},
	{diskDesc("write_time_seconds_total", "The total number of seconds spent by all writes."), prometheus.CounterValue,
		func(s blockdevice.IOStats) float64 { return float64(s.WriteTicks) * diskTickSeconds }},
	{diskDesc("io_now", "The number of I/Os currently in progress."), prometheus.GaugeValue,
		func(s blockdevice.IOStats) float64 { return float64(s.IOsInProgress) }},
	{diskDesc("io_time_seconds_total", "Total seconds spent doing I/Os."), prometheus.CounterValue,
		func(s blockdevice.IOStats) float64 { return float64(s.IOsTotalTicks) * diskTickSeconds }},
	{diskDesc("io_time_weighted_seconds_total", "The weighted number of seconds spent doing I/Os."), prometheus.CounterValue,
		func(s blockdevice.IOStats) float64 { return float64(s.WeightedIOTicks) * diskTickSeconds }},
	{diskDesc("discards_completed_total", "The total number of discards completed successfully."), prometheus.CounterValue,
		func(s blockdevice.IOStats) float64 { return float64(s.DiscardIOs) }},
	{diskDesc("discards_merged_total", "The total number of discards merged."), prometheus.CounterValue,
		func(s blockdevice.IOStats) float64 { return float64(s.DiscardMerges) }},
	{diskDesc("discarded_sectors_total", "The total number of sectors discarded successfully."), prometheus.CounterValue,
		func(s blockdevice.IOStats) float64 { return float64(s.DiscardSectors) }},
	{diskDesc("discard_time_seconds_total", "The total number of seconds spent by all discards."), prometheus.CounterValue,
		func(s blockdevice.IOStats) float64 { return float64(s.DiscardTicks) * diskTickSeconds }},
	{diskDesc("flush_requests_total", "The total number of flush requests completed successfully."), prometheus.CounterValue,
		func(s blockdevice.IOStats) float64 { return float64(s.FlushRequestsCompleted) }},
	{diskDesc("flush_requests_time_seconds_total", "The total number of seconds spent by all flush requests."), prometheus.CounterValue,
		func(s blockdevice.IOStats) float64 { return float64(s.TimeSpentFlushing) * diskTickSeconds }},
}

type diskPart struct {
	fs blockdevice.FS
}

func newDiskPart(cfg HostConfig) (*diskPart, error) {
	// blockdevice.NewFS insists on a sysfs mount point, but ProcDiskstats
	// reads only /proc/diskstats; sysfs is only checked to exist.
	sys := cfg.SysPath
	if sys == "" {
		sys = "/sys"
	}
	fs, err := blockdevice.NewFS(cfg.ProcPath, sys)
	if err != nil {
		return nil, fmt.Errorf("opening procfs at %s for diskstats: %w", cfg.ProcPath, err)
	}
	return &diskPart{fs: fs}, nil
}

func (*diskPart) name() string { return collectorDisk }

func (*diskPart) describe(ch chan<- *prometheus.Desc) {
	for _, s := range diskStats {
		ch <- s.desc
	}
}

func (d *diskPart) update(_ *runState, b *batch) error {
	stats, err := d.fs.ProcDiskstats()
	if err != nil {
		return fmt.Errorf("reading diskstats: %w", err)
	}
	kept := 0
	for _, s := range stats {
		if !diskDevice.MatchString(s.DeviceName) {
			continue
		}
		if kept == maxDiskDevices {
			b.drop(reasonCap, 1)
			continue
		}
		kept++
		// IoStatsCount includes the major, minor and name fields.
		present := s.IoStatsCount - 3
		for i, st := range diskStats {
			if i >= present {
				break
			}
			b.add(st.desc, st.vt, st.value(s.IOStats), s.DeviceName)
		}
	}
	return nil
}

func pressureDesc(name, help, resource string) *prometheus.Desc {
	return prometheus.NewDesc("node_pressure_"+name, help+", from /proc/pressure/"+resource+".", nil, nil)
}

// psiResources lists what node_exporter exports per resource: cpu only its
// "some" line, irq only "full" (the kernel reports no "some" for it).
var psiResources = []struct {
	resource   string
	some, full *prometheus.Desc
}{
	{"cpu", pressureDesc("cpu_waiting_seconds_total", "Total time in seconds that processes have waited for CPU time", "cpu"), nil},
	{"io",
		pressureDesc("io_waiting_seconds_total", "Total time in seconds that processes have waited due to IO congestion", "io"),
		pressureDesc("io_stalled_seconds_total", "Total time in seconds no process could make progress due to IO congestion", "io")},
	{"memory",
		pressureDesc("memory_waiting_seconds_total", "Total time in seconds that processes have waited for memory", "memory"),
		pressureDesc("memory_stalled_seconds_total", "Total time in seconds no process could make progress due to memory congestion", "memory")},
	{"irq", nil, pressureDesc("irq_stalled_seconds_total", "Total time in seconds no process could make progress due to IRQ congestion", "irq")},
}

type pressurePart struct {
	fs procfs.FS
}

func newPressurePart(cfg HostConfig) (*pressurePart, error) {
	fs, err := procfs.NewFS(cfg.ProcPath)
	if err != nil {
		return nil, fmt.Errorf("opening procfs at %s for pressure: %w", cfg.ProcPath, err)
	}
	return &pressurePart{fs: fs}, nil
}

func (*pressurePart) name() string { return collectorPressure }

func (*pressurePart) describe(ch chan<- *prometheus.Desc) {
	for _, r := range psiResources {
		for _, d := range []*prometheus.Desc{r.some, r.full} {
			if d != nil {
				ch <- d
			}
		}
	}
}

// update skips a resource whose file does not exist (a kernel without PSI,
// or without IRQ time accounting for irq), and emits nothing when PSI is
// compiled in but disabled at boot. Any other read error fails the
// collector: a permission error is what a missing AppArmor rule looks like,
// and it must not pass for "no PSI".
func (p *pressurePart) update(_ *runState, b *batch) error {
	for _, r := range psiResources {
		st, err := p.fs.PSIStatsForResource(r.resource)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case errors.Is(err, syscall.EOPNOTSUPP):
			return nil
		case err != nil:
			return fmt.Errorf("reading pressure/%s: %w", r.resource, err)
		}
		if r.some != nil {
			if st.Some == nil {
				return fmt.Errorf("pressure/%s has no some line", r.resource)
			}
			b.add(r.some, prometheus.CounterValue, float64(st.Some.Total)/1e6)
		}
		if r.full != nil {
			if st.Full == nil {
				return fmt.Errorf("pressure/%s has no full line", r.resource)
			}
			b.add(r.full, prometheus.CounterValue, float64(st.Full.Total)/1e6)
		}
	}
	return nil
}
