package collector

import (
	"fmt"
	"sort"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/TBording/haos-exporter/haos_exporter/internal/sanitize"
	"github.com/TBording/haos-exporter/haos_exporter/internal/supervisor"
)

var (
	unameInfoDesc = prometheus.NewDesc("node_uname_info",
		"Host identity. nodename and release come from the Supervisor's /host/info, not from the container.",
		[]string{"nodename", "release", "machine", "sysname"}, nil)
	diskLifeTimeDesc = prometheus.NewDesc(namespace+"_host_disk_life_time_used_ratio",
		"Share of the data disk's rated life used (0-1). Absent when the Supervisor cannot read it.", nil, nil)

	versionInfoDesc = prometheus.NewDesc(namespace+"_component_version_info",
		"Installed and latest version of a component.", []string{"component", "version", "version_latest"}, nil)
	updateAvailableDesc = prometheus.NewDesc(namespace+"_component_update_available",
		"1 if the Supervisor reports an update for the component.", []string{"component"}, nil)
	updatesPendingDesc = prometheus.NewDesc(namespace+"_updates_pending",
		"Pending updates by type; for type app, the number of apps with an update.", []string{"type"}, nil)
	bootSlotDesc = prometheus.NewDesc(namespace+"_os_boot_slot_info",
		"HAOS A/B boot slot state.", []string{"slot", "state", "status", "version"}, nil)

	supervisorHealthyDesc = prometheus.NewDesc(namespace+"_supervisor_healthy",
		"1 if the Supervisor reports itself healthy.", nil, nil)
	supervisorSupportedDesc = prometheus.NewDesc(namespace+"_supervisor_supported",
		"1 if the Supervisor reports the installation as supported.", nil, nil)
	featureFlagDesc = prometheus.NewDesc(namespace+"_supervisor_feature_flag",
		"Supervisor feature flag state.", []string{"flag"}, nil)

	appInfoDesc = prometheus.NewDesc(namespace+"_app_info",
		"Installed app.", []string{"slug", "name", "version", "version_latest", "repository"}, nil)
	appStateDesc = prometheus.NewDesc(namespace+"_app_state",
		"App state as a StateSet: 1 for the current state, 0 for the others.", []string{"slug", "state"}, nil)
	appUpdateDesc = prometheus.NewDesc(namespace+"_app_update_available",
		"1 if an update is available for the app.", []string{"slug"}, nil)

	unhealthyDesc = prometheus.NewDesc(namespace+"_resolution_unhealthy",
		"Reason the Supervisor marks the system unhealthy.", []string{"reason"}, nil)
	unsupportedDesc = prometheus.NewDesc(namespace+"_resolution_unsupported",
		"Reason the Supervisor marks the system unsupported.", []string{"reason"}, nil)
	issuesDesc = prometheus.NewDesc(namespace+"_resolution_issues",
		"Resolution center issues per (type, context).", []string{"type", "context"}, nil)
	suggestionsDesc = prometheus.NewDesc(namespace+"_resolution_suggestions",
		"Resolution center suggestions per (type, context).", []string{"type", "context"}, nil)

	backupsDesc = prometheus.NewDesc(namespace+"_backups",
		"Number of backups by type.", []string{"type"}, nil)
	backupsSizeDesc = prometheus.NewDesc(namespace+"_backups_size_bytes",
		"Total size of backups by type.", []string{"type"}, nil)
	backupLatestDesc = prometheus.NewDesc(namespace+"_backup_latest_timestamp_seconds",
		"Date of the newest backup by type, in Unix seconds. Absent when there is none.", []string{"type"}, nil)
)

// componentMetrics emits the version, update and pending series shared by
// core, supervisor and os.
func componentMetrics(b *batch, component, version, latest string, update bool) {
	b.gauge(versionInfoDesc, 1, component, sanitize.Label(version), sanitize.Label(latest))
	b.gauge(updateAvailableDesc, boolFloat(update), component)
	b.gauge(updatesPendingDesc, boolFloat(update), component)
}

// host_info

type hostInfoPart struct {
	uname func() (sysname, machine string, err error)
}

func (hostInfoPart) name() string { return collectorHostInfo }

func (hostInfoPart) describe(ch chan<- *prometheus.Desc) {
	ch <- unameInfoDesc
	ch <- diskLifeTimeDesc
}

func (p hostInfoPart) update(s *runState, b *batch) error {
	var info supervisor.HostInfo
	if err := s.api.Get(s.ctx, supervisor.PathHostInfo, &info); err != nil {
		return err
	}
	sysname, machine, err := p.uname()
	if err != nil {
		return fmt.Errorf("uname: %w", err)
	}
	b.gauge(unameInfoDesc, 1, sanitize.Label(info.Hostname), sanitize.Label(info.Kernel),
		sanitize.Label(machine), sanitize.Label(sysname))
	if info.DiskLifeTime != nil {
		b.gauge(diskLifeTimeDesc, *info.DiskLifeTime/100)
	}
	return nil
}

// os_info

type osInfoPart struct{}

func (osInfoPart) name() string { return collectorOSInfo }

func (osInfoPart) describe(ch chan<- *prometheus.Desc) {
	ch <- versionInfoDesc
	ch <- updateAvailableDesc
	ch <- updatesPendingDesc
	ch <- bootSlotDesc
}

func (osInfoPart) update(s *runState, b *batch) error {
	var info supervisor.OSInfo
	if err := s.api.Get(s.ctx, supervisor.PathOSInfo, &info); err != nil {
		return err
	}
	componentMetrics(b, "os", info.Version, info.VersionLatest, info.UpdateAvailable)
	// Sorted, so that the cap keeps the same slots on every scrape.
	slots := make([]string, 0, len(info.BootSlots))
	for slot := range info.BootSlots {
		slots = append(slots, slot)
	}
	sort.Strings(slots)
	capped := newCapSet(b, maxEnumSeries)
	for _, slot := range slots {
		label := sanitize.Label(slot)
		if !capped.admit(label) {
			continue
		}
		st := info.BootSlots[slot]
		b.gauge(bootSlotDesc, 1, label, sanitize.Label(st.State),
			sanitize.Label(st.Status), sanitize.Label(st.Version))
	}
	return nil
}

// core_info

type coreInfoPart struct{}

func (coreInfoPart) name() string { return collectorCoreInfo }

func (coreInfoPart) describe(ch chan<- *prometheus.Desc) {
	ch <- versionInfoDesc
	ch <- updateAvailableDesc
	ch <- updatesPendingDesc
}

func (coreInfoPart) update(s *runState, b *batch) error {
	var info supervisor.CoreInfo
	if err := s.api.Get(s.ctx, supervisor.PathCoreInfo, &info); err != nil {
		return err
	}
	componentMetrics(b, "core", info.Version, info.VersionLatest, info.UpdateAvailable)
	// The Core probe dials this address on every scrape until the next
	// successful poll replaces it.
	s.core.Store(&info)
	return nil
}

// supervisor_info

type supervisorInfoPart struct{}

func (supervisorInfoPart) name() string { return collectorSupervisorInfo }

func (supervisorInfoPart) describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{versionInfoDesc, updateAvailableDesc, updatesPendingDesc,
		supervisorHealthyDesc, supervisorSupportedDesc, featureFlagDesc,
		appInfoDesc, appStateDesc, appUpdateDesc} {
		ch <- d
	}
}

func (supervisorInfoPart) update(s *runState, b *batch) error {
	var info supervisor.SupervisorInfo
	if err := s.api.Get(s.ctx, supervisor.PathSupervisorInfo, &info); err != nil {
		return err
	}
	componentMetrics(b, "supervisor", info.Version, info.VersionLatest, info.UpdateAvailable)
	b.gauge(supervisorHealthyDesc, boolFloat(info.Healthy))
	b.gauge(supervisorSupportedDesc, boolFloat(info.Supported))
	flags := newCapSet(b, maxEnumSeries)
	for _, flag := range featureFlagOrder(info.FeatureFlags) {
		if label := sanitize.Label(flag); flags.admit(label) {
			b.gauge(featureFlagDesc, boolFloat(info.FeatureFlags[flag]), label)
		}
	}

	// The pending count covers every app the Supervisor lists, including
	// ones whose series are dropped below.
	pending, kept := 0, 0
	for _, app := range info.Apps {
		if app.UpdateAvailable {
			pending++
		}
		if !validSlug(app.Slug) {
			b.drop(reasonInvalidSlug, 1)
			continue
		}
		if kept == maxApps {
			b.drop(reasonCap, 1)
			continue
		}
		kept++
		b.gauge(appInfoDesc, 1, app.Slug, sanitize.Label(app.Name), sanitize.Label(app.Version),
			sanitize.Label(app.VersionLatest), sanitize.Label(app.Repository))
		current := appState(app.State)
		for _, st := range appStates {
			b.gauge(appStateDesc, boolFloat(st == current), app.Slug, st)
		}
		b.gauge(appUpdateDesc, boolFloat(app.UpdateAvailable), app.Slug)
	}
	b.gauge(updatesPendingDesc, float64(pending), "app")
	return nil
}

// resolution_info

type resolutionInfoPart struct{}

func (resolutionInfoPart) name() string { return collectorResolutionInfo }

func (resolutionInfoPart) describe(ch chan<- *prometheus.Desc) {
	ch <- unhealthyDesc
	ch <- unsupportedDesc
	ch <- issuesDesc
	ch <- suggestionsDesc
}

func (resolutionInfoPart) update(s *runState, b *batch) error {
	var info supervisor.ResolutionInfo
	if err := s.api.Get(s.ctx, supervisor.PathResolutionInfo, &info); err != nil {
		return err
	}
	reasons(b, unhealthyDesc, info.Unhealthy)
	reasons(b, unsupportedDesc, info.Unsupported)
	resolutionPairs(b, issuesDesc, info.Issues)
	resolutionPairs(b, suggestionsDesc, info.Suggestions)
	return nil
}

// reasons emits one series per distinct reason, in the Supervisor's order;
// reasons past maxEnumSeries are dropped and counted.
func reasons(b *batch, desc *prometheus.Desc, list []string) {
	capped := newCapSet(b, maxEnumSeries)
	for _, r := range list {
		if label := sanitize.Label(r); capped.admit(label) {
			b.gauge(desc, 1, label)
		}
	}
}

// resolutionPairs counts items per (type, context). The first
// maxResolutionPairs distinct pairs, in the Supervisor's order, are kept;
// each further pair is dropped and counted.
func resolutionPairs(b *batch, desc *prometheus.Desc, items []supervisor.ResolutionItem) {
	type pair struct{ typ, ctx string }
	counts := map[pair]int{}
	dropped := map[pair]bool{}
	var order []pair
	for _, it := range items {
		p := pair{sanitize.Label(it.Type), sanitize.Label(it.Context)}
		if _, kept := counts[p]; kept {
			counts[p]++
			continue
		}
		if len(order) == maxResolutionPairs {
			if !dropped[p] {
				dropped[p] = true
				b.drop(reasonCap, 1)
			}
			continue
		}
		order = append(order, p)
		counts[p] = 1
	}
	for _, p := range order {
		b.gauge(desc, float64(counts[p]), p.typ, p.ctx)
	}
}

// backups_info

type backupsInfoPart struct{}

func (backupsInfoPart) name() string { return collectorBackupsInfo }

func (backupsInfoPart) describe(ch chan<- *prometheus.Desc) {
	ch <- backupsDesc
	ch <- backupsSizeDesc
	ch <- backupLatestDesc
}

func (backupsInfoPart) update(s *runState, b *batch) error {
	var info supervisor.BackupsInfo
	if err := s.api.Get(s.ctx, supervisor.PathBackupsInfo, &info); err != nil {
		return err
	}
	type agg struct {
		count  int
		size   float64
		latest float64
		dated  bool
	}
	byType := map[string]*agg{"full": {}, "partial": {}}
	for _, bk := range info.Backups {
		t := backupType(bk.Type)
		a := byType[t]
		if a == nil {
			a = &agg{}
			byType[t] = a
		}
		a.count++
		a.size += bk.SizeBytes
		// A date that does not parse still counts the backup; it just
		// cannot be the newest.
		if d, err := parseBackupDate(bk.Date); err == nil {
			if ts := unixSeconds(d); !a.dated || ts > a.latest {
				a.latest, a.dated = ts, true
			}
		}
	}
	types := make([]string, 0, len(byType))
	for t := range byType {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, t := range types {
		a := byType[t]
		b.gauge(backupsDesc, float64(a.count), t)
		b.gauge(backupsSizeDesc, a.size, t)
		if a.count > 0 && a.dated {
			b.gauge(backupLatestDesc, a.latest, t)
		}
	}
	return nil
}
