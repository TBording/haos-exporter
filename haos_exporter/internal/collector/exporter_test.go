package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/TBording/haos-exporter/haos_exporter/internal/supervisor"
)

var sixPaths = []string{
	supervisor.PathBackupsInfo,
	supervisor.PathCoreInfo,
	supervisor.PathHostInfo,
	supervisor.PathOSInfo,
	supervisor.PathResolutionInfo,
	supervisor.PathSupervisorInfo,
}

var supervisorCollectors = []string{
	collectorHostInfo, collectorOSInfo, collectorCoreInfo, collectorSupervisorInfo,
	collectorResolutionInfo, collectorBackupsInfo, collectorCoreProbe,
}

func TestSupervisorGolden(t *testing.T) {
	e := newEnv(t, envOpts{})
	g := gatherer(t, e.exporter, "haos_exporter_collector_duration_seconds")
	compareGolden(t, g, "supervisor.prom")

	text := exposition(t, g)
	for _, leak := range []string{"CANARY", "172.30.32", "127.0.0.1", "0a1b2c3d", "Example partial", "00000000000000000000000000000002"} {
		if bytes.Contains(text, []byte(leak)) {
			t.Errorf("exposition contains %q", leak)
		}
	}
	if strings.Contains(e.logs.String(), "CANARY") || strings.Contains(e.logs.String(), testToken) {
		t.Errorf("logs leak a secret: %s", e.logs.String())
	}
}

func TestStartPollsEachPathOnceAndScrapesCallNoSupervisor(t *testing.T) {
	e := newEnv(t, envOpts{})
	// newEnv ran Start: one poll of every path.
	if got := e.sup.seen(); !reflect.DeepEqual(got, sixPaths) {
		t.Fatalf("Start: Supervisor saw %v, want %v", got, sixPaths)
	}
	e.sup.reset()
	for scrape := 1; scrape <= 3; scrape++ {
		e.core.reset()
		mfs := collectOnce(t, e.exporter)
		if got := e.sup.seen(); len(got) != 0 {
			t.Fatalf("scrape %d: Supervisor saw %v, want nothing", scrape, got)
		}
		// The Core probe is not a Supervisor call and stays per scrape.
		if got := e.core.seen(); !reflect.DeepEqual(got, []string{ManifestPath}) {
			t.Fatalf("scrape %d: Core saw %v", scrape, got)
		}
		for _, c := range supervisorCollectors {
			if successOf(t, mfs, c) != 1 {
				t.Fatalf("scrape %d: %s failed; logs: %s", scrape, c, e.logs)
			}
		}
	}
}

func TestPollCadence(t *testing.T) {
	e := newEnv(t, envOpts{})
	wantInterval := map[string]float64{
		collectorSupervisorInfo: 60, collectorResolutionInfo: 60,
		collectorHostInfo: 300, collectorOSInfo: 300, collectorCoreInfo: 300, collectorBackupsInfo: 300,
	}
	mfs := collectOnce(t, e.exporter)
	for c, want := range wantInterval {
		if v, ok := value(mfs, "haos_exporter_collector_poll_interval_seconds", map[string]string{"collector": c}); !ok || v != want {
			t.Errorf("poll interval for %s = %v (%t), want %v", c, v, ok, want)
		}
	}
	for _, c := range []string{collectorHost, collectorCoreProbe} {
		if _, ok := value(mfs, "haos_exporter_collector_poll_interval_seconds", map[string]string{"collector": c}); ok {
			t.Errorf("%s runs per scrape but reports a poll interval", c)
		}
	}

	e.sup.reset()
	e.ticks.tick(t, time.Minute, 2)
	frequent := []string{supervisor.PathResolutionInfo, supervisor.PathSupervisorInfo}
	waitFor(t, "the one-minute polls", func() bool { return len(e.sup.seen()) == 2 })
	if got := e.sup.seen(); !reflect.DeepEqual(got, frequent) {
		t.Fatalf("one-minute tick polled %v, want %v", got, frequent)
	}

	e.sup.reset()
	e.ticks.tick(t, 5*time.Minute, 4)
	infrequent := []string{supervisor.PathBackupsInfo, supervisor.PathCoreInfo, supervisor.PathHostInfo, supervisor.PathOSInfo}
	waitFor(t, "the five-minute polls", func() bool { return len(e.sup.seen()) == 4 })
	if got := e.sup.seen(); !reflect.DeepEqual(got, infrequent) {
		t.Fatalf("five-minute tick polled %v, want %v", got, infrequent)
	}
}

// switchable serves the fixture until fail is set, then answers with the
// failure handler.
type switchable struct {
	mu   sync.Mutex
	fail http.HandlerFunc
}

func (s *switchable) set(h http.HandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail = h
}

func (s *switchable) handler(t *testing.T, fixture string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		h := s.fail
		s.mu.Unlock()
		if h != nil {
			h(w, r)
			return
		}
		w.Write(readFixture(t, fixture))
	}
}

func TestScrapeDoesNotWaitOnSupervisor(t *testing.T) {
	var sw switchable
	e := newEnv(t, envOpts{override: map[string]http.HandlerFunc{
		supervisor.PathSupervisorInfo: sw.handler(t, "supervisor_info.json"),
	}})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	sw.set(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	// A poll is now hanging on the Supervisor.
	e.ticks.tick(t, time.Minute, 2)
	waitFor(t, "the hanging poll to start", func() bool {
		for _, p := range e.sup.seen() {
			if p == supervisor.PathSupervisorInfo {
				return true
			}
		}
		return false
	})
	start := time.Now()
	mfs := collectOnce(t, e.exporter)
	if d := time.Since(start); d > time.Second {
		t.Fatalf("scrape took %v while a poll hung", d)
	}
	if successOf(t, mfs, collectorSupervisorInfo) != 1 {
		t.Fatal("the previous good poll should still be served")
	}
	if _, ok := value(mfs, "haos_component_version_info", map[string]string{"component": "supervisor"}); !ok {
		t.Fatal("cached supervisor series missing")
	}
}

func TestFailedPollKeepsItsLastSuccessTimestamp(t *testing.T) {
	var sw switchable
	e := newEnv(t, envOpts{override: map[string]http.HandlerFunc{
		supervisor.PathOSInfo: sw.handler(t, "os_info.json"),
	}})
	firstPoll := float64(e.clock.Now().Unix())
	mfs := collectOnce(t, e.exporter)
	for _, c := range []string{collectorOSInfo, collectorSupervisorInfo} {
		if v, _ := value(mfs, "haos_exporter_collector_last_success_timestamp_seconds", map[string]string{"collector": c}); v != firstPoll {
			t.Fatalf("%s last success = %v, want %v", c, v, firstPoll)
		}
	}

	sw.set(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"result":"error","message":"boom"}`))
	})
	e.clock.Advance(5 * time.Minute)
	e.sup.reset()
	e.ticks.tick(t, 5*time.Minute, 4)
	waitFor(t, "the five-minute polls", func() bool { return len(e.sup.seen()) == 4 })
	waitFor(t, "os_info to report the failure", func() bool {
		return successOf(t, collectOnce(t, e.exporter), collectorOSInfo) == 0
	})

	mfs = collectOnce(t, e.exporter)
	if _, ok := value(mfs, "haos_os_boot_slot_info", nil); ok {
		t.Error("a failed poll must not serve the previous poll's series")
	}
	if v, _ := value(mfs, "haos_exporter_collector_last_success_timestamp_seconds", map[string]string{"collector": collectorOSInfo}); v != firstPoll {
		t.Errorf("os_info last success = %v, want the first poll's %v", v, firstPoll)
	}
	if v, _ := value(mfs, "haos_exporter_collector_last_success_timestamp_seconds", map[string]string{"collector": collectorCoreInfo}); v != firstPoll+300 {
		t.Errorf("core_info last success = %v, want %v", v, firstPoll+300)
	}
	if successOf(t, mfs, collectorCoreInfo) != 1 {
		t.Error("a failing os_info affected core_info")
	}
}

func TestNeverSucceededTimestampIsZero(t *testing.T) {
	e := newEnv(t, envOpts{override: map[string]http.HandlerFunc{
		supervisor.PathBackupsInfo: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) },
	}})
	mfs := collectOnce(t, e.exporter)
	if successOf(t, mfs, collectorBackupsInfo) != 0 {
		t.Fatal("backups_info reported success")
	}
	if v, ok := value(mfs, "haos_exporter_collector_last_success_timestamp_seconds", map[string]string{"collector": collectorBackupsInfo}); !ok || v != 0 {
		t.Fatalf("never-succeeded timestamp = %v (%t), want 0", v, ok)
	}
}

func TestCoreProbeUsesLastKnownAddress(t *testing.T) {
	e := newEnv(t, envOpts{})
	// Break /core/info after Start has read it once. The pollers are idle
	// until the tick below, whose channel send orders this write before
	// their next read.
	e.exporter.api = failingGetter{path: supervisor.PathCoreInfo, next: e.exporter.api}
	e.ticks.tick(t, 5*time.Minute, 4)
	waitFor(t, "core_info to report the failure", func() bool {
		return successOf(t, collectOnce(t, e.exporter), collectorCoreInfo) == 0
	})
	e.core.reset()
	mfs := collectOnce(t, e.exporter)
	if successOf(t, mfs, collectorCoreProbe) != 1 {
		t.Fatalf("core_probe failed; logs: %s", e.logs)
	}
	if up, _ := value(mfs, "haos_core_up", nil); up != 1 {
		t.Fatal("core probe did not reach Core at the last known address")
	}
	if got := e.core.seen(); !reflect.DeepEqual(got, []string{ManifestPath}) {
		t.Fatalf("Core saw %v", got)
	}
}

// failingGetter fails one path and passes the rest to next.
type failingGetter struct {
	path string
	next Getter
}

func (f failingGetter) Get(ctx context.Context, path string, out any) error {
	if path == f.path {
		return errors.New("injected failure")
	}
	return f.next.Get(ctx, path, out)
}

func TestDurationReported(t *testing.T) {
	e := newEnv(t, envOpts{})
	mfs := collectOnce(t, e.exporter)
	for _, c := range supervisorCollectors {
		v, ok := value(mfs, "haos_exporter_collector_duration_seconds", map[string]string{"collector": c})
		if !ok || v < 0 {
			t.Fatalf("duration for %s = %v, %t", c, v, ok)
		}
	}
}

func TestOneFailingEndpointOnlyFailsItsCollector(t *testing.T) {
	fail500 := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"result":"error","message":"boom"}`))
	}
	oversized := func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"result":"ok","data":{"backups":[],"pad":"` + strings.Repeat("x", supervisor.MaxBodyBytes) + `"}}`))
	}
	tests := []struct {
		name       string
		path       string
		handler    http.HandlerFunc
		failed     []string
		absent     []string
		coreProbed bool
	}{
		{
			name: "os_info 500", path: supervisor.PathOSInfo, handler: fail500,
			failed:     []string{collectorOSInfo},
			absent:     []string{"haos_os_boot_slot_info"},
			coreProbed: true,
		},
		{
			name: "backups_info oversized", path: supervisor.PathBackupsInfo, handler: oversized,
			failed:     []string{collectorBackupsInfo},
			absent:     []string{"haos_backups", "haos_backups_size_bytes", "haos_backup_latest_timestamp_seconds"},
			coreProbed: true,
		},
		{
			name: "resolution_info plain-text 403", path: supervisor.PathResolutionInfo,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("403: Forbidden"))
			},
			failed:     []string{collectorResolutionInfo},
			absent:     []string{"haos_resolution_issues", "haos_resolution_suggestions", "haos_resolution_unhealthy"},
			coreProbed: true,
		},
		{
			// /core/info feeds both core_info and the probe.
			name: "core_info 500", path: supervisor.PathCoreInfo, handler: fail500,
			failed:     []string{collectorCoreInfo, collectorCoreProbe},
			absent:     []string{"haos_core_up"},
			coreProbed: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, envOpts{override: map[string]http.HandlerFunc{tt.path: tt.handler}})
			mfs := collectOnce(t, e.exporter)
			failed := map[string]bool{}
			for _, c := range tt.failed {
				failed[c] = true
			}
			for _, c := range supervisorCollectors {
				want := 1.0
				if failed[c] {
					want = 0
				}
				if got := successOf(t, mfs, c); got != want {
					t.Errorf("%s success = %v, want %v", c, got, want)
				}
			}
			for _, name := range tt.absent {
				if n := countSeries(mfs, name); n != 0 {
					t.Errorf("%s has %d series, want none", name, n)
				}
			}
			// The failed collector emitted nothing else, the others did.
			if tt.path == supervisor.PathOSInfo {
				if _, ok := value(mfs, "haos_component_version_info", map[string]string{"component": "os"}); ok {
					t.Error("os version emitted by a failed collector")
				}
				if _, ok := value(mfs, "haos_component_version_info", map[string]string{"component": "core"}); !ok {
					t.Error("core version missing")
				}
			}
			if got := len(e.core.seen()) > 0; got != tt.coreProbed {
				t.Errorf("core probed = %t, want %t", got, tt.coreProbed)
			}
			if got := e.sup.seen(); !reflect.DeepEqual(got, sixPaths) {
				t.Errorf("Supervisor saw %v", got)
			}
		})
	}
}

// panicPart fails by panicking.
type panicPart struct{}

func (panicPart) name() string                     { return "panics" }
func (panicPart) describe(chan<- *prometheus.Desc) {}
func (panicPart) update(*runState, *batch) error   { panic("boom") }

func TestPanickingCollectorIsContained(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.exporter.live = append(e.exporter.live, panicPart{})
	polled := newPolledPart(panicPolledPart{}, time.Minute)
	e.exporter.polled = append(e.exporter.polled, polled)
	e.exporter.poll(context.Background(), polled)
	mfs := collectOnce(t, e.exporter)
	for _, c := range []string{"panics", "panics_polled"} {
		if successOf(t, mfs, c) != 0 {
			t.Fatalf("panicking collector %s reported success", c)
		}
	}
	if successOf(t, mfs, collectorSupervisorInfo) != 1 {
		t.Fatal("a panic in one collector affected another")
	}
}

type panicPolledPart struct{ panicPart }

func (panicPolledPart) name() string { return "panics_polled" }

func TestConcurrentCollect(t *testing.T) {
	e := newEnv(t, envOpts{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			ch := make(chan prometheus.Metric)
			go func() {
				e.exporter.Collect(ch)
				close(ch)
			}()
			for range ch {
			}
		})
	}
	wg.Wait()
}

func appsJSON(n int) []byte {
	type app struct {
		Name            string `json:"name"`
		Slug            string `json:"slug"`
		Version         string `json:"version"`
		VersionLatest   string `json:"version_latest"`
		UpdateAvailable bool   `json:"update_available"`
		State           string `json:"state"`
		Repository      string `json:"repository"`
	}
	apps := make([]app, n)
	for i := range apps {
		apps[i] = app{fmt.Sprintf("App %d", i), fmt.Sprintf("local_app_%03d", i), "1.0.0", "1.0.0", i%2 == 0, "started", "local"}
	}
	b, _ := json.Marshal(map[string]any{"result": "ok", "data": map[string]any{
		"version": "2026.01.0", "version_latest": "2026.01.0", "healthy": true, "supported": true,
		"feature_flags": map[string]bool{}, "addons": apps,
	}})
	return b
}

func TestAppCapAndDroppedCounter(t *testing.T) {
	body := appsJSON(300)
	e := newEnv(t, envOpts{override: map[string]http.HandlerFunc{
		supervisor.PathSupervisorInfo: func(w http.ResponseWriter, _ *http.Request) { w.Write(body) },
	}})
	// Drops are counted per poll, not per scrape.
	for scrape, wantDropped := range []float64{44, 44, 88} {
		if scrape == 2 {
			e.exporter.pollAll(context.Background())
		}
		mfs := collectOnce(t, e.exporter)
		if n := countSeries(mfs, "haos_app_info"); n != maxApps {
			t.Fatalf("scrape %d: %d haos_app_info series, want %d", scrape+1, n, maxApps)
		}
		if n := countSeries(mfs, "haos_app_state"); n != maxApps*len(appStates) {
			t.Fatalf("scrape %d: %d haos_app_state series", scrape+1, n)
		}
		got, _ := value(mfs, "haos_exporter_series_dropped_total", map[string]string{"collector": collectorSupervisorInfo, "reason": reasonCap})
		if got != wantDropped {
			t.Fatalf("scrape %d: dropped{cap} = %v, want %v", scrape+1, got, wantDropped)
		}
		if pending, _ := value(mfs, "haos_updates_pending", map[string]string{"type": "app"}); pending != 150 {
			t.Fatalf("pending apps = %v, want 150 (every listed app)", pending)
		}
		if _, ok := value(mfs, "haos_app_info", map[string]string{"slug": "local_app_256"}); ok {
			t.Fatal("app beyond the cap emitted")
		}
		if _, ok := value(mfs, "haos_app_info", map[string]string{"slug": "local_app_255"}); !ok {
			t.Fatal("last app within the cap missing")
		}
	}
}

func TestResolutionPairCap(t *testing.T) {
	var issues []map[string]any
	for i := range 70 {
		issues = append(issues, map[string]any{"type": fmt.Sprintf("type_%02d", i), "context": "system", "uuid": fmt.Sprintf("%032d", i)})
	}
	// Repeats of a kept pair add to its count; repeats of a dropped pair are
	// dropped once.
	issues = append(issues,
		map[string]any{"type": "type_00", "context": "system"},
		map[string]any{"type": "type_69", "context": "system"},
	)
	body, _ := json.Marshal(map[string]any{"result": "ok", "data": map[string]any{
		"unsupported": []string{}, "unhealthy": []string{}, "issues": issues, "suggestions": []any{},
	}})
	e := newEnv(t, envOpts{override: map[string]http.HandlerFunc{
		supervisor.PathResolutionInfo: func(w http.ResponseWriter, _ *http.Request) { w.Write(body) },
	}})
	mfs := collectOnce(t, e.exporter)
	if n := countSeries(mfs, "haos_resolution_issues"); n != maxResolutionPairs {
		t.Fatalf("%d issue series, want %d", n, maxResolutionPairs)
	}
	if v, _ := value(mfs, "haos_resolution_issues", map[string]string{"type": "type_00"}); v != 2 {
		t.Fatalf("type_00 count = %v, want 2", v)
	}
	if v, _ := value(mfs, "haos_exporter_series_dropped_total", map[string]string{"collector": collectorResolutionInfo, "reason": reasonCap}); v != 6 {
		t.Fatalf("dropped resolution pairs = %v, want 6", v)
	}
	if n := countSeries(mfs, "haos_resolution_suggestions"); n != 0 {
		t.Fatalf("%d suggestion series, want 0", n)
	}
}

// TestEnumFamilyCaps covers the families whose labels are Supervisor enums:
// each keeps at most maxEnumSeries series and counts the rest.
func TestEnumFamilyCaps(t *testing.T) {
	flags := map[string]bool{flagV2API: true}
	for i := range 100 {
		// Every name sorts before supervisor_v2_api, which must still be kept.
		flags[fmt.Sprintf("flag_%03d", i)] = false
	}
	slots := map[string]any{}
	for i := range 70 {
		slots[fmt.Sprintf("slot_%02d", i)] = map[string]any{"state": "inactive", "status": "good", "version": "16.0"}
	}
	var unhealthy, unsupported []string
	for i := range 70 {
		unhealthy = append(unhealthy, fmt.Sprintf("reason_%02d", i))
	}
	// A repeat, and a value that sanitises to a kept one, add nothing.
	unhealthy = append(unhealthy, "reason_00", "reason_01\x00")
	for i := range 80 {
		unsupported = append(unsupported, fmt.Sprintf("reason_%02d", i))
	}
	sup, _ := json.Marshal(map[string]any{"result": "ok", "data": map[string]any{
		"version": "2026.01.0", "version_latest": "2026.01.0", "healthy": true, "supported": true,
		"feature_flags": flags, "addons": []any{},
	}})
	osInfo, _ := json.Marshal(map[string]any{"result": "ok", "data": map[string]any{
		"version": "16.0", "version_latest": "16.0", "boot_slots": slots,
	}})
	res, _ := json.Marshal(map[string]any{"result": "ok", "data": map[string]any{
		"unhealthy": unhealthy, "unsupported": unsupported, "issues": []any{}, "suggestions": []any{},
	}})
	serve := func(b []byte) http.HandlerFunc { return func(w http.ResponseWriter, _ *http.Request) { w.Write(b) } }
	e := newEnv(t, envOpts{override: map[string]http.HandlerFunc{
		supervisor.PathSupervisorInfo: serve(sup),
		supervisor.PathOSInfo:         serve(osInfo),
		supervisor.PathResolutionInfo: serve(res),
	}})
	for scrape := 1; scrape <= 2; scrape++ {
		if scrape == 2 {
			e.exporter.pollAll(context.Background())
		}
		mfs := collectOnce(t, e.exporter)
		for _, c := range supervisorCollectors {
			if successOf(t, mfs, c) != 1 {
				t.Fatalf("scrape %d: %s failed; logs: %s", scrape, c, e.logs)
			}
		}
		for _, name := range []string{"haos_supervisor_feature_flag", "haos_os_boot_slot_info", "haos_resolution_unhealthy", "haos_resolution_unsupported"} {
			if n := countSeries(mfs, name); n != maxEnumSeries {
				t.Errorf("scrape %d: %s has %d series, want %d", scrape, name, n, maxEnumSeries)
			}
		}
		if v, ok := value(mfs, "haos_supervisor_feature_flag", map[string]string{"flag": flagV2API}); !ok || v != 1 {
			t.Errorf("scrape %d: %s = %v (%t), want 1", scrape, flagV2API, v, ok)
		}
		if _, ok := value(mfs, "haos_supervisor_feature_flag", map[string]string{"flag": "flag_063"}); ok {
			t.Errorf("scrape %d: flag_063 kept; the cap must leave room for %s", scrape, flagV2API)
		}
		// Slots are capped in sorted order, so the same ones survive every scrape.
		if _, ok := value(mfs, "haos_os_boot_slot_info", map[string]string{"slot": "slot_63"}); !ok {
			t.Errorf("scrape %d: slot_63 missing", scrape)
		}
		if _, ok := value(mfs, "haos_os_boot_slot_info", map[string]string{"slot": "slot_64"}); ok {
			t.Errorf("scrape %d: slot_64 kept", scrape)
		}
		for collector, perScrape := range map[string]float64{
			collectorSupervisorInfo: 101 - maxEnumSeries,
			collectorOSInfo:         70 - maxEnumSeries,
			collectorResolutionInfo: (70 - maxEnumSeries) + (80 - maxEnumSeries),
		} {
			want := perScrape * float64(scrape)
			if v, _ := value(mfs, "haos_exporter_series_dropped_total", map[string]string{"collector": collector, "reason": reasonCap}); v != want {
				t.Errorf("scrape %d: dropped{%s,cap} = %v, want %v", scrape, collector, v, want)
			}
		}
	}
}

func TestLabelSanitisationAndSlugRejection(t *testing.T) {
	long := strings.Repeat("é", 200)
	body, _ := json.Marshal(map[string]any{"result": "ok", "data": map[string]any{
		"version": "2026.01.0\x07", "version_latest": long, "healthy": true, "supported": true,
		"feature_flags": map[string]bool{"flag\nwith\tcontrols": true},
		"addons": []map[string]any{
			{"name": long, "slug": "local_long", "version": "1\x00.0", "state": "started", "repository": "local"},
			{"name": "x", "slug": "", "state": "started"},
			{"name": "x", "slug": strings.Repeat("a", 65), "state": "started"},
			{"name": "x", "slug": "../escape", "state": "started"},
			{"name": "x", "slug": "ünicode", "state": "started"},
		},
	}})
	e := newEnv(t, envOpts{override: map[string]http.HandlerFunc{
		supervisor.PathSupervisorInfo: func(w http.ResponseWriter, _ *http.Request) { w.Write(body) },
	}})
	mfs := collectOnce(t, e.exporter)
	if n := countSeries(mfs, "haos_app_info"); n != 1 {
		t.Fatalf("%d apps emitted, want 1", n)
	}
	if v, _ := value(mfs, "haos_exporter_series_dropped_total", map[string]string{"collector": collectorSupervisorInfo, "reason": reasonInvalidSlug}); v != 4 {
		t.Fatalf("invalid slugs dropped = %v, want 4", v)
	}
	if _, ok := value(mfs, "haos_app_info", map[string]string{"slug": "local_long", "name": strings.Repeat("é", 128), "version": "1.0"}); !ok {
		t.Fatalf("sanitised app labels not found: %v", mfs["haos_app_info"])
	}
	if _, ok := value(mfs, "haos_component_version_info", map[string]string{"component": "supervisor", "version": "2026.01.0", "version_latest": strings.Repeat("é", 128)}); !ok {
		t.Fatalf("sanitised supervisor version not found: %v", mfs["haos_component_version_info"])
	}
	if _, ok := value(mfs, "haos_supervisor_feature_flag", map[string]string{"flag": "flagwithcontrols"}); !ok {
		t.Fatal("sanitised feature flag not found")
	}
}

func TestAppStateSet(t *testing.T) {
	states := []string{"started", "stopped", "startup", "error", "unknown", "rebuilding", ""}
	var apps []map[string]any
	for i, st := range states {
		apps = append(apps, map[string]any{"name": st, "slug": fmt.Sprintf("local_%d", i), "state": st})
	}
	body, _ := json.Marshal(map[string]any{"result": "ok", "data": map[string]any{"addons": apps}})
	e := newEnv(t, envOpts{override: map[string]http.HandlerFunc{
		supervisor.PathSupervisorInfo: func(w http.ResponseWriter, _ *http.Request) { w.Write(body) },
	}})
	mfs := collectOnce(t, e.exporter)
	for i, st := range states {
		want := st
		if st == "rebuilding" || st == "" {
			want = "unknown"
		}
		slug := fmt.Sprintf("local_%d", i)
		sum := 0.0
		for _, s := range appStates {
			v, ok := value(mfs, "haos_app_state", map[string]string{"slug": slug, "state": s})
			if !ok {
				t.Fatalf("%s: no series for state %s", slug, s)
			}
			if (v == 1) != (s == want) {
				t.Fatalf("%s (state %q): %s = %v", slug, st, s, v)
			}
			sum += v
		}
		if sum != 1 {
			t.Fatalf("%s: StateSet sums to %v", slug, sum)
		}
	}
}

func TestBackups(t *testing.T) {
	serve := func(backups []map[string]any) http.HandlerFunc {
		body, _ := json.Marshal(map[string]any{"result": "ok", "data": map[string]any{"backups": backups, "days_until_stale": 30}})
		return func(w http.ResponseWriter, _ *http.Request) { w.Write(body) }
	}
	tests := []struct {
		name    string
		backups []map[string]any
		count   map[string]float64
		size    map[string]float64
		latest  map[string]float64 // absent types must have no series
	}{
		{
			name:    "none",
			backups: []map[string]any{},
			count:   map[string]float64{"full": 0, "partial": 0},
			size:    map[string]float64{"full": 0, "partial": 0},
			latest:  map[string]float64{},
		},
		{
			name: "full, partial and other",
			backups: []map[string]any{
				{"type": "full", "date": "2026-09-28T02:59:51.123456+00:00", "size_bytes": 100},
				{"type": "full", "date": "2026-09-27T02:59:51+00:00", "size_bytes": 50},
				{"type": "partial", "date": "2026-09-01T00:00:00.5+02:00", "size_bytes": 10},
				{"type": "something_new", "date": "2026-01-01T00:00:00+00:00", "size_bytes": 1},
			},
			count:  map[string]float64{"full": 2, "partial": 1, "other": 1},
			size:   map[string]float64{"full": 150, "partial": 10, "other": 1},
			latest: map[string]float64{"full": 1790564391.123456, "partial": 1788213600.5, "other": 1767225600},
		},
		{
			name: "undated backup still counts",
			backups: []map[string]any{
				{"type": "partial", "date": "2026-09-28 02:59:51", "size_bytes": 7},
			},
			count:  map[string]float64{"full": 0, "partial": 1},
			size:   map[string]float64{"full": 0, "partial": 7},
			latest: map[string]float64{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, envOpts{override: map[string]http.HandlerFunc{supervisor.PathBackupsInfo: serve(tt.backups)}})
			mfs := collectOnce(t, e.exporter)
			if n := countSeries(mfs, "haos_backups"); n != len(tt.count) {
				t.Fatalf("%d haos_backups series, want %d", n, len(tt.count))
			}
			for typ, want := range tt.count {
				if v, ok := value(mfs, "haos_backups", map[string]string{"type": typ}); !ok || v != want {
					t.Errorf("haos_backups{type=%s} = %v (%t), want %v", typ, v, ok, want)
				}
				if v, ok := value(mfs, "haos_backups_size_bytes", map[string]string{"type": typ}); !ok || v != tt.size[typ] {
					t.Errorf("haos_backups_size_bytes{type=%s} = %v (%t), want %v", typ, v, ok, tt.size[typ])
				}
			}
			if n := countSeries(mfs, "haos_backup_latest_timestamp_seconds"); n != len(tt.latest) {
				t.Fatalf("%d latest series, want %d", n, len(tt.latest))
			}
			for typ, want := range tt.latest {
				if v, ok := value(mfs, "haos_backup_latest_timestamp_seconds", map[string]string{"type": typ}); !ok || v != want {
					t.Errorf("latest{type=%s} = %v (%t), want %v", typ, v, ok, want)
				}
			}
		})
	}
}

func TestDiskLifeTime(t *testing.T) {
	for _, tt := range []struct {
		raw     any
		want    float64
		present bool
	}{
		{nil, 0, false},
		{0.0, 0, true},
		{37.5, 0.375, true},
	} {
		body, _ := json.Marshal(map[string]any{"result": "ok", "data": map[string]any{
			"hostname": "homeassistant", "kernel": "6.12.40-haos", "disk_life_time": tt.raw,
		}})
		e := newEnv(t, envOpts{override: map[string]http.HandlerFunc{
			supervisor.PathHostInfo: func(w http.ResponseWriter, _ *http.Request) { w.Write(body) },
		}})
		mfs := collectOnce(t, e.exporter)
		v, ok := value(mfs, "haos_host_disk_life_time_used_ratio", nil)
		if ok != tt.present || v != tt.want {
			t.Errorf("disk_life_time %v: got %v (%t), want %v (%t)", tt.raw, v, ok, tt.want, tt.present)
		}
		if _, ok := value(mfs, "node_uname_info", map[string]string{"nodename": "homeassistant", "release": "6.12.40-haos", "machine": "x86_64", "sysname": "Linux"}); !ok {
			t.Error("node_uname_info missing or wrong")
		}
	}
}
