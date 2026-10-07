package collector

import (
	"regexp"
	"sort"
	"time"
)

// Collector names, used as the "collector" label.
const (
	collectorHost           = "host"
	collectorDisk           = "disk"
	collectorPressure       = "pressure"
	collectorHostInfo       = "host_info"
	collectorOSInfo         = "os_info"
	collectorCoreInfo       = "core_info"
	collectorSupervisorInfo = "supervisor_info"
	collectorResolutionInfo = "resolution_info"
	collectorBackupsInfo    = "backups_info"
	collectorCoreProbe      = "core_probe"
	collectorTLS            = "tls"
)

// Reasons for haos_exporter_series_dropped_total.
const (
	reasonInvalidSlug = "invalid_slug"
	reasonCap         = "cap"
)

// Cardinality caps.
const (
	maxApps            = 256
	maxResolutionPairs = 64
	// maxEnumSeries caps each family whose label values are Supervisor
	// enums: feature flags, boot slots, and unhealthy and unsupported
	// reasons. Supervisor 2026.09.2 defines 2 flags, 2 slots, 10 unhealthy
	// and 24 unsupported reasons.
	maxEnumSeries = 64
)

// flagV2API is the feature flag that moves the app list behind role
// manager. DESIGN.md names its series as the signal for that break, so the
// cap never drops it.
const flagV2API = "supervisor_v2_api"

// capSet admits the first limit distinct label values it is asked about.
// Each further distinct value is counted once in the batch as dropped by the
// cap.
type capSet struct {
	b     *batch
	limit int
	n     int
	kept  map[string]bool
}

func newCapSet(b *batch, limit int) *capSet {
	return &capSet{b: b, limit: limit, kept: map[string]bool{}}
}

// admit reports whether v is within the cap.
func (c *capSet) admit(v string) bool {
	if kept, seen := c.kept[v]; seen {
		return kept
	}
	kept := c.n < c.limit
	c.kept[v] = kept
	if kept {
		c.n++
	} else {
		c.b.drop(reasonCap, 1)
	}
	return kept
}

// featureFlagOrder returns the flag names sorted, with flagV2API first so
// that the cap never drops it.
func featureFlagOrder(flags map[string]bool) []string {
	names := make([]string, 0, len(flags))
	for f := range flags {
		if f != flagV2API {
			names = append(names, f)
		}
	}
	sort.Strings(names)
	if _, ok := flags[flagV2API]; ok {
		names = append([]string{flagV2API}, names...)
	}
	return names
}

// slugPattern is the Supervisor's own slug pattern (RE_SLUG), bounded.
var slugPattern = regexp.MustCompile(`^[-_.A-Za-z0-9]{1,64}$`)

func validSlug(s string) bool { return slugPattern.MatchString(s) }

// appStates are the states haos_app_state reports, one series each.
var appStates = []string{"started", "stopped", "startup", "error", "unknown"}

// appState maps a Supervisor app state onto appStates; anything else is
// "unknown".
func appState(s string) string {
	for _, st := range appStates {
		if s == st {
			return s
		}
	}
	return "unknown"
}

// backupType maps a backup type onto full, partial or other.
func backupType(t string) string {
	switch t {
	case "full", "partial":
		return t
	default:
		return "other"
	}
}

// parseBackupDate parses the Supervisor's backup date, a Python isoformat()
// string such as 2026-09-28T02:59:51.123456+00:00. isoformat() omits the
// fraction when it is zero; RFC 3339 parsing accepts both forms.
func parseBackupDate(s string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, s)
}

// unixSeconds returns t as fractional Unix seconds at microsecond precision,
// the precision the Supervisor writes.
func unixSeconds(t time.Time) float64 {
	return float64(t.UnixMicro()) / 1e6
}
