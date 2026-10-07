package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"

	"github.com/TBording/haos-exporter/haos_exporter/internal/supervisor"
)

var update = flag.Bool("update", false, "rewrite the golden files")

const testToken = "test-token-not-a-secret"

var fixtureFor = map[string]string{
	supervisor.PathHostInfo:       "host_info.json",
	supervisor.PathOSInfo:         "os_info.json",
	supervisor.PathCoreInfo:       "core_info.json",
	supervisor.PathSupervisorInfo: "supervisor_info.json",
	supervisor.PathResolutionInfo: "resolution_info.json",
	supervisor.PathBackupsInfo:    "backups_info.json",
}

func testdata(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", "testdata"}, parts...)...)
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(testdata("supervisor", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// recorder notes the requests a test server saw.
type recorder struct {
	mu    sync.Mutex
	paths []string
	auth  []string
}

func (r *recorder) note(req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.paths = append(r.paths, req.URL.Path)
	r.auth = append(r.auth, req.Header.Get("Authorization"))
}

func (r *recorder) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]string(nil), r.paths...)
	sort.Strings(out)
	return out
}

func (r *recorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.paths, r.auth = nil, nil
}

type envOpts struct {
	// override replaces the Supervisor's answer for a path.
	override map[string]http.HandlerFunc
	// core answers the Core probe; nil answers 200.
	core http.HandlerFunc
	// coreTLS serves the Core probe over TLS.
	coreTLS bool
	// coreInfo edits the /core/info data after it has been pointed at the
	// test Core server.
	coreInfo func(map[string]any)
	// probeTimeout defaults to 2 s.
	probeTimeout time.Duration
	host         *HostConfig
}

type env struct {
	exporter *Exporter
	sup      *recorder
	core     *recorder
	logs     *bytes.Buffer
	clock    *fakeClock
	ticks    *fakeTickers
}

// fakeClock is a settable clock for the exporter's now.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeTickers replaces the poll tickers: each interval gets one channel, and
// nothing ticks unless a test sends on it.
type fakeTickers struct {
	mu    sync.Mutex
	chans map[time.Duration]chan time.Time
	asked []time.Duration
}

func (f *fakeTickers) new(d time.Duration) (<-chan time.Time, func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, d)
	c, ok := f.chans[d]
	if !ok {
		c = make(chan time.Time)
		f.chans[d] = c
	}
	return c, func() {}
}

// tick fires every poller on interval d once. The send blocks until each
// poller has received it; the poll itself then runs asynchronously.
func (f *fakeTickers) tick(t *testing.T, d time.Duration, pollers int) {
	t.Helper()
	f.mu.Lock()
	c, ok := f.chans[d]
	f.mu.Unlock()
	if !ok {
		t.Fatalf("no poller on interval %v", d)
	}
	for range pollers {
		select {
		case c <- time.Time{}:
		case <-time.After(5 * time.Second):
			t.Fatalf("poller on %v did not take the tick", d)
		}
	}
}

func newEnv(t *testing.T, o envOpts) *env {
	t.Helper()
	e := &env{
		sup: &recorder{}, core: &recorder{}, logs: &bytes.Buffer{},
		clock: &fakeClock{t: time.Unix(1790000000, 0)},
		ticks: &fakeTickers{chans: map[time.Duration]chan time.Time{}},
	}

	coreHandler := o.core
	if coreHandler == nil {
		coreHandler = func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{"name":"Home Assistant"}`)) }
	}
	coreH := func(w http.ResponseWriter, r *http.Request) {
		e.core.note(r)
		coreHandler(w, r)
	}
	var coreSrv *httptest.Server
	if o.coreTLS {
		coreSrv = httptest.NewTLSServer(http.HandlerFunc(coreH))
	} else {
		coreSrv = httptest.NewServer(http.HandlerFunc(coreH))
	}
	t.Cleanup(coreSrv.Close)
	cu, _ := url.Parse(coreSrv.URL)
	coreHost, corePortS, _ := net.SplitHostPort(cu.Host)
	corePort, _ := strconv.Atoi(corePortS)

	supSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.sup.note(r)
		if h, ok := o.override[r.URL.Path]; ok {
			h(w, r)
			return
		}
		name, ok := fixtureFor[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("404: Not Found"))
			return
		}
		body := readFixture(t, name)
		if r.URL.Path == supervisor.PathCoreInfo {
			var doc map[string]any
			if err := json.Unmarshal(body, &doc); err != nil {
				t.Error(err)
			}
			data := doc["data"].(map[string]any)
			data["ip_address"] = coreHost
			data["port"] = corePort
			data["ssl"] = o.coreTLS
			if o.coreInfo != nil {
				o.coreInfo(data)
			}
			body, _ = json.Marshal(doc)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	t.Cleanup(supSrv.Close)

	client, err := supervisor.New(supSrv.URL, testToken)
	if err != nil {
		t.Fatal(err)
	}
	timeout := o.probeTimeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	exp, err := New(Config{
		Logger:     slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Supervisor: client,
		CoreProbe:  NewCoreProbe(timeout),
		Uname:      func() (string, string, error) { return "Linux", "x86_64", nil },
		Host:       o.host,
	})
	if err != nil {
		t.Fatal(err)
	}
	exp.now = e.clock.Now
	exp.newTicker = e.ticks.new
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	exp.Start(ctx)
	e.exporter = exp
	return e
}

// waitFor polls cond until it holds or 5 s pass.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// gatherer registers c in a pedantic registry and hides the given metric
// families, so that golden files need not hold non-deterministic values.
func gatherer(t *testing.T, c prometheus.Collector, hide ...string) prometheus.Gatherer {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatal(err)
	}
	return prometheus.GathererFunc(func() ([]*dto.MetricFamily, error) {
		mfs, err := reg.Gather()
		out := mfs[:0]
		for _, mf := range mfs {
			keep := true
			for _, h := range hide {
				if mf.GetName() == h {
					keep = false
				}
			}
			if keep {
				out = append(out, mf)
			}
		}
		return out, err
	})
}

func exposition(t *testing.T, g prometheus.Gatherer) []byte {
	t.Helper()
	mfs, err := g.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	enc := expfmt.NewEncoder(&buf, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, mf := range mfs {
		if err := enc.Encode(mf); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

// compareGolden compares g against testdata/golden/name, or rewrites it
// with -update.
func compareGolden(t *testing.T, g prometheus.Gatherer, name string) {
	t.Helper()
	path := testdata("golden", name)
	if *update {
		if err := os.WriteFile(path, exposition(t, g), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := testutil.GatherAndCompare(g, f); err != nil {
		t.Fatal(err)
	}
}

// collectOnce gathers c once and returns its families by name.
func collectOnce(t *testing.T, c prometheus.Collector) map[string]*dto.MetricFamily {
	t.Helper()
	mfs, err := gatherer(t, c).Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*dto.MetricFamily{}
	for _, mf := range mfs {
		out[mf.GetName()] = mf
	}
	return out
}

// value returns the value of the series of family name whose labels include
// all of want, and whether one exists.
func value(mfs map[string]*dto.MetricFamily, name string, want map[string]string) (float64, bool) {
	mf, ok := mfs[name]
	if !ok {
		return 0, false
	}
	for _, m := range mf.GetMetric() {
		labels := map[string]string{}
		for _, lp := range m.GetLabel() {
			labels[lp.GetName()] = lp.GetValue()
		}
		match := true
		for k, v := range want {
			if labels[k] != v {
				match = false
			}
		}
		if !match {
			continue
		}
		switch {
		case m.Gauge != nil:
			return m.GetGauge().GetValue(), true
		case m.Counter != nil:
			return m.GetCounter().GetValue(), true
		}
	}
	return 0, false
}

func successOf(t *testing.T, mfs map[string]*dto.MetricFamily, collector string) float64 {
	t.Helper()
	v, ok := value(mfs, "haos_exporter_collector_success", map[string]string{"collector": collector})
	if !ok {
		t.Fatalf("no haos_exporter_collector_success for %s", collector)
	}
	return v
}

func countSeries(mfs map[string]*dto.MetricFamily, name string) int {
	if mf, ok := mfs[name]; ok {
		return len(mf.GetMetric())
	}
	return 0
}
