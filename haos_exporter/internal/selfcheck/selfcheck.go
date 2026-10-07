// Package selfcheck verifies at start-up that the container runs with the
// confinement the design relies on, and exports the result as
// haos_exporter_security_check{check}.
//
// A failed check is a warning, never fatal: the exporter keeps serving.
package selfcheck

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"

	"github.com/TBording/haos-exporter/haos_exporter/internal/supervisor"
)

// Check names, used as the "check" label.
const (
	CheckNonroot             = "nonroot"
	CheckNoCapabilities      = "no_capabilities"
	CheckAppArmorEnforced    = "apparmor_enforced"
	CheckAppArmorBlocksWrite = "apparmor_blocks_write"
	CheckRoleLeastPrivilege  = "role_least_privilege"
)

// Getter is the read side of the Supervisor client.
type Getter interface {
	Get(ctx context.Context, path string, out any) error
}

// Config holds the paths and hooks the checks use; tests inject them.
type Config struct {
	// ProcPath is where procfs is mounted, normally /proc.
	ProcPath string
	// ShmPath is a world-writable tmpfs, normally /dev/shm. DAC allows the
	// write, so only AppArmor can refuse it.
	ShmPath string
	// Geteuid defaults to os.Geteuid.
	Geteuid func() int
	// CreateTemp defaults to os.CreateTemp.
	CreateTemp func(dir, pattern string) (*os.File, error)
	// Supervisor is used for the role check.
	Supervisor Getter
}

// Result is the outcome of one check.
type Result struct {
	Check  string
	Passed bool
	Detail string
}

// Run executes every check once, in a fixed order.
func Run(ctx context.Context, cfg Config) []Result {
	if cfg.Geteuid == nil {
		cfg.Geteuid = os.Geteuid
	}
	if cfg.CreateTemp == nil {
		cfg.CreateTemp = os.CreateTemp
	}
	return []Result{
		nonroot(cfg),
		noCapabilities(cfg),
		appArmorEnforced(cfg),
		appArmorBlocksWrite(cfg),
		roleLeastPrivilege(ctx, cfg),
	}
}

// Metric returns haos_exporter_security_check with one series per result.
func Metric(results []Result) prometheus.Collector {
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "haos_exporter_security_check",
		Help: "Start-up security self-check: 1 if the check passed (the container is confined as intended), 0 if not.",
	}, []string{"check"})
	for _, r := range results {
		v := 0.0
		if r.Passed {
			v = 1
		}
		g.WithLabelValues(r.Check).Set(v)
	}
	return g
}

func nonroot(cfg Config) Result {
	uid := cfg.Geteuid()
	return Result{CheckNonroot, uid != 0, fmt.Sprintf("effective uid %d", uid)}
}

func noCapabilities(cfg Config) Result {
	r := Result{Check: CheckNoCapabilities}
	pfs, err := procfs.NewFS(cfg.ProcPath)
	if err != nil {
		r.Detail = "opening procfs: " + err.Error()
		return r
	}
	self, err := pfs.Self()
	if err != nil {
		r.Detail = "resolving self: " + err.Error()
		return r
	}
	st, err := self.NewStatus()
	if err != nil {
		r.Detail = "reading status: " + err.Error()
		return r
	}
	r.Passed = st.CapEff == 0
	r.Detail = fmt.Sprintf("CapEff %016x", st.CapEff)
	return r
}

// appArmorEnforced reads the AppArmor label of this process. The
// LSM-specific attr/apparmor/current is authoritative when present; the
// generic attr/current is the fallback on kernels without it.
func appArmorEnforced(cfg Config) Result {
	r := Result{Check: CheckAppArmorEnforced}
	var label string
	var errs []string
	for _, p := range []string{"self/attr/apparmor/current", "self/attr/current"} {
		b, err := os.ReadFile(filepath.Join(cfg.ProcPath, p))
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		label = strings.TrimRight(string(b), "\x00\n ")
		if label != "" {
			break
		}
	}
	if label == "" {
		r.Detail = "no AppArmor label: " + strings.Join(errs, "; ")
		return r
	}
	r.Passed = strings.HasSuffix(label, " (enforce)")
	r.Detail = "label " + label
	return r
}

// appArmorBlocksWrite tries to create a file in /dev/shm and passes only when
// that fails with a permission error (EACCES or EPERM). /dev/shm is a
// world-writable tmpfs, so DAC allows the write and only AppArmor should
// refuse it. Any other error, such as ENOENT when /dev/shm is missing, proves
// nothing about the profile and fails the check; the error is kept in Detail.
func appArmorBlocksWrite(cfg Config) Result {
	r := Result{Check: CheckAppArmorBlocksWrite}
	f, err := cfg.CreateTemp(cfg.ShmPath, ".haos-exporter-selfcheck-*")
	if err == nil {
		name := f.Name()
		f.Close()
		if rmErr := os.Remove(name); rmErr != nil {
			r.Detail = fmt.Sprintf("write to %s succeeded; removing the probe file failed: %v", cfg.ShmPath, rmErr)
			return r
		}
		r.Detail = fmt.Sprintf("write to %s succeeded (probe file removed)", cfg.ShmPath)
		return r
	}
	// On Linux, fs.ErrPermission matches exactly EACCES and EPERM.
	if errors.Is(err, fs.ErrPermission) {
		r.Passed = true
		r.Detail = fmt.Sprintf("write to %s refused: %v", cfg.ShmPath, err)
		return r
	}
	errno := "no errno"
	var e syscall.Errno
	if errors.As(err, &e) {
		errno = fmt.Sprintf("errno %d", int(e))
	}
	r.Detail = fmt.Sprintf("write to %s failed with a non-permission error (%s: %v), which proves nothing about AppArmor", cfg.ShmPath, errno, err)
	return r
}

// roleLeastPrivilege expects GET /addons, a manager-only path, to be
// refused. The request discards any body it gets.
func roleLeastPrivilege(ctx context.Context, cfg Config) Result {
	r := Result{Check: CheckRoleLeastPrivilege}
	if cfg.Supervisor == nil {
		r.Detail = "no Supervisor client"
		return r
	}
	err := cfg.Supervisor.Get(ctx, supervisor.PathAddons, nil)
	switch {
	case errors.Is(err, supervisor.ErrForbidden):
		r.Passed = true
		r.Detail = "GET " + supervisor.PathAddons + " refused with 403"
	case err == nil:
		r.Detail = "GET " + supervisor.PathAddons + " succeeded: the token has a role above default"
	default:
		r.Detail = "inconclusive: " + err.Error()
	}
	return r
}
