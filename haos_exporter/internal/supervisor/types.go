package supervisor

// The structs below hold only the fields the exporter uses. Fields that can
// carry secrets (options, ingress_entry, ingress_url) are deliberately
// absent, so they are never decoded and can never reach a label or a log
// line. Unknown fields are ignored by encoding/json.

// HostInfo is the subset of GET /host/info the exporter reads.
type HostInfo struct {
	Hostname string `json:"hostname"`
	Kernel   string `json:"kernel"`
	// DiskLifeTime is the percentage of the data disk's rated life used, or
	// nil when the Supervisor cannot read it (always on a virtual disk).
	DiskLifeTime *float64 `json:"disk_life_time"`
}

// OSInfo is the subset of GET /os/info the exporter reads.
type OSInfo struct {
	Version         string              `json:"version"`
	VersionLatest   string              `json:"version_latest"`
	UpdateAvailable bool                `json:"update_available"`
	BootSlots       map[string]BootSlot `json:"boot_slots"`
}

// BootSlot is one entry of /os/info boot_slots.
type BootSlot struct {
	State   string `json:"state"`
	Status  string `json:"status"`
	Version string `json:"version"`
}

// CoreInfo is the subset of GET /core/info the exporter reads.
type CoreInfo struct {
	Version         string `json:"version"`
	VersionLatest   string `json:"version_latest"`
	UpdateAvailable bool   `json:"update_available"`
	IPAddress       string `json:"ip_address"`
	Port            int    `json:"port"`
	SSL             bool   `json:"ssl"`
}

// SupervisorInfo is the subset of GET /supervisor/info the exporter reads.
type SupervisorInfo struct {
	Version         string          `json:"version"`
	VersionLatest   string          `json:"version_latest"`
	UpdateAvailable bool            `json:"update_available"`
	Healthy         bool            `json:"healthy"`
	Supported       bool            `json:"supported"`
	FeatureFlags    map[string]bool `json:"feature_flags"`
	// Apps is the v1 "addons" list, marked deprecated by the Supervisor. It
	// is the only app list the default role can read. It is nil when the
	// field is absent or null, which is how its removal will show; an empty
	// list is a non-nil pointer to an empty slice.
	Apps *[]App `json:"addons"`
}

// App is one entry of the /supervisor/info app list.
type App struct {
	Name            string `json:"name"`
	Slug            string `json:"slug"`
	Version         string `json:"version"`
	VersionLatest   string `json:"version_latest"`
	UpdateAvailable bool   `json:"update_available"`
	State           string `json:"state"`
	Repository      string `json:"repository"`
}

// ResolutionInfo is the subset of GET /resolution/info the exporter reads.
type ResolutionInfo struct {
	Unsupported []string         `json:"unsupported"`
	Unhealthy   []string         `json:"unhealthy"`
	Issues      []ResolutionItem `json:"issues"`
	Suggestions []ResolutionItem `json:"suggestions"`
}

// ResolutionItem is an issue or suggestion. Its uuid is not decoded: it is
// random per item and must never become a label.
type ResolutionItem struct {
	Type    string `json:"type"`
	Context string `json:"context"`
}

// BackupsInfo is the subset of GET /backups/info the exporter reads.
type BackupsInfo struct {
	Backups []Backup `json:"backups"`
}

// Backup is one backup. Its name and slug are not decoded.
type Backup struct {
	Type      string  `json:"type"`
	Date      string  `json:"date"`
	SizeBytes float64 `json:"size_bytes"`
}
