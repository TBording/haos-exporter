// Package collector turns the Supervisor API and the host's /proc into
// Prometheus metrics.
//
// Collectors come in two kinds. The live ones (host, disk, pressure,
// core_probe, tls) run on every scrape and make no Supervisor calls. The
// Supervisor-backed ones are polled in the background on their own interval,
// and a scrape only replays the result of each one's latest poll, so it never
// waits on the Supervisor and the scrape interval does not set how often the
// Supervisor is asked. The Supervisor logs every app request at INFO; see
// DESIGN.md.
//
// Each collector reports haos_exporter_collector_success and
// haos_exporter_collector_duration_seconds for its last run. A collector
// whose last run failed emits only those two series (success 0), plus, for a
// polled one, its last-success timestamp and poll interval; the others are
// unaffected.
package collector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/TBording/haos-exporter/haos_exporter/internal/supervisor"
)

const namespace = "haos"

// Getter is the read side of the Supervisor client.
type Getter interface {
	Get(ctx context.Context, path string, out any) error
}

// Prober checks whether Home Assistant Core answers HTTP.
type Prober interface {
	Probe(ctx context.Context, ip string, port int, useTLS bool) (bool, error)
}

// Config selects and wires the collectors.
type Config struct {
	Logger *slog.Logger

	// Supervisor enables the Supervisor-backed collectors. Nil disables
	// them.
	Supervisor Getter
	// CoreProbe is required when Supervisor is set.
	CoreProbe Prober
	// Uname returns the kernel's sysname and machine for node_uname_info.
	// Nil uses uname(2).
	Uname func() (sysname, machine string, err error)

	// Host enables the /proc and statfs collector. Nil disables it.
	Host *HostConfig
	// TLS enables the provided-certificate collector. Nil, or neither
	// Server nor ClientCA set, disables it.
	TLS *TLSConfig
}

var (
	successDesc = prometheus.NewDesc(
		"haos_exporter_collector_success",
		"1 if the collector's last run (for a Supervisor-backed collector, its last poll) succeeded; 0 if it failed, in which case none of its own series are emitted.",
		[]string{"collector"}, nil,
	)
	durationDesc = prometheus.NewDesc(
		"haos_exporter_collector_duration_seconds",
		"Duration of the collector's last run.",
		[]string{"collector"}, nil,
	)
	lastSuccessDesc = prometheus.NewDesc(
		"haos_exporter_collector_last_success_timestamp_seconds",
		"Time of the Supervisor-backed collector's last successful poll, in Unix seconds; 0 if it has not succeeded since the exporter started.",
		[]string{"collector"}, nil,
	)
	pollIntervalDesc = prometheus.NewDesc(
		"haos_exporter_collector_poll_interval_seconds",
		"How often the Supervisor-backed collector is polled.",
		[]string{"collector"}, nil,
	)
)

// Poll intervals. They set the Supervisor's log volume, since it logs every
// request at INFO: 2 × 1,440 + 4 × 288 ≈ 4,000 lines a day.
const (
	// pollFrequent is for state that changes by itself: health, app state,
	// resolution issues.
	pollFrequent = time.Minute
	// pollInfrequent is for versions, pending updates, backups and host
	// identity.
	pollInfrequent = 5 * time.Minute
)

// part is one collector run by the Exporter.
type part interface {
	name() string
	describe(ch chan<- *prometheus.Desc)
	update(s *runState, b *batch) error
}

// Exporter is the prometheus.Collector that runs the live parts on every
// scrape and serves the polled parts' latest results.
type Exporter struct {
	logger  *slog.Logger
	api     Getter
	live    []part
	polled  []*polledPart
	core    atomic.Pointer[supervisor.CoreInfo]
	dropped *prometheus.CounterVec
	now     func() time.Time
	// newTicker returns a channel that ticks every d and a stop function.
	newTicker func(d time.Duration) (<-chan time.Time, func())
}

// New returns an Exporter for cfg.
func New(cfg Config) (*Exporter, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	e := &Exporter{
		logger:    logger,
		api:       cfg.Supervisor,
		now:       time.Now,
		newTicker: realTicker,
		dropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "haos_exporter_series_dropped_total",
			Help: "Apps, feature flags, boot slots, resolution reasons, resolution (type, context) pairs or disk devices left out of the metrics, by cap or failed validation.",
		}, []string{"collector", "reason"}),
	}
	if cfg.Host != nil {
		h, err := newHostPart(*cfg.Host)
		if err != nil {
			return nil, err
		}
		d, err := newDiskPart(*cfg.Host)
		if err != nil {
			return nil, err
		}
		p, err := newPressurePart(*cfg.Host)
		if err != nil {
			return nil, err
		}
		e.live = append(e.live, h, d, p)
		e.dropped.WithLabelValues(collectorDisk, reasonCap)
	}
	if cfg.Supervisor != nil {
		if cfg.CoreProbe == nil {
			return nil, errors.New("collector: CoreProbe is required with Supervisor")
		}
		uname := cfg.Uname
		if uname == nil {
			uname = systemUname
		}
		e.polled = append(e.polled,
			newPolledPart(hostInfoPart{uname: uname}, pollInfrequent),
			newPolledPart(osInfoPart{}, pollInfrequent),
			newPolledPart(coreInfoPart{}, pollInfrequent),
			newPolledPart(supervisorInfoPart{}, pollFrequent),
			newPolledPart(resolutionInfoPart{}, pollFrequent),
			newPolledPart(backupsInfoPart{}, pollInfrequent),
		)
		e.live = append(e.live, coreProbePart{probe: cfg.CoreProbe})
		// Start the drop counters at 0 so that increase() works from the
		// first drop.
		e.dropped.WithLabelValues(collectorOSInfo, reasonCap)
		e.dropped.WithLabelValues(collectorSupervisorInfo, reasonInvalidSlug)
		e.dropped.WithLabelValues(collectorSupervisorInfo, reasonCap)
		e.dropped.WithLabelValues(collectorResolutionInfo, reasonCap)
	}
	if cfg.TLS != nil && (cfg.TLS.Server || cfg.TLS.ClientCA) {
		e.live = append(e.live, tlsPart{cfg: *cfg.TLS})
	}
	return e, nil
}

// Describe implements prometheus.Collector.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- successDesc
	ch <- durationDesc
	if len(e.polled) > 0 {
		ch <- lastSuccessDesc
		ch <- pollIntervalDesc
	}
	for _, p := range e.live {
		p.describe(ch)
	}
	for _, p := range e.polled {
		p.describe(ch)
	}
	e.dropped.Describe(ch)
}

// Start polls every Supervisor-backed collector once and waits for that
// round, then polls each one on its own interval until ctx is done. It must
// be called once, before the exporter is scraped; until then the polled
// collectors report success 0. The first round takes at most the Supervisor
// client's request timeout.
func (e *Exporter) Start(ctx context.Context) {
	e.pollAll(ctx)
	for _, p := range e.polled {
		tick, stop := e.newTicker(p.interval)
		go func() {
			defer stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick:
					e.poll(ctx, p)
				}
			}
		}()
	}
}

// pollAll polls every polled part concurrently and waits for all of them.
func (e *Exporter) pollAll(ctx context.Context) {
	var wg sync.WaitGroup
	for _, p := range e.polled {
		wg.Go(func() { e.poll(ctx, p) })
	}
	wg.Wait()
}

// poll runs one polled part and stores its result for the scrapes that
// follow. Drops are counted here, once per poll.
func (e *Exporter) poll(ctx context.Context, p *polledPart) {
	start := e.now()
	b := newBatch()
	err := safeUpdate(p, &runState{ctx: ctx, api: e.api, core: &e.core, logger: e.logger}, b)
	if err == nil {
		err = b.err
	}
	end := e.now()
	if err != nil {
		e.logger.Warn("collector failed", "collector", p.name(), "err", err)
	} else {
		for reason, n := range b.drops {
			e.dropped.WithLabelValues(p.name(), reason).Add(float64(n))
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ran = true
	p.duration = end.Sub(start).Seconds()
	p.success = err == nil
	p.metrics = nil
	if err == nil {
		p.metrics = b.metrics
		p.lastSuccess = end
	}
}

// Collect implements prometheus.Collector. It runs the live parts
// concurrently and replays each polled part's latest result. It makes no
// Supervisor request: the live parts get no Supervisor client.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	s := &runState{ctx: context.Background(), core: &e.core, logger: e.logger}
	var wg sync.WaitGroup
	for _, p := range e.live {
		wg.Go(func() { e.run(p, s, ch) })
	}
	for _, p := range e.polled {
		p.collect(ch)
	}
	wg.Wait()
	e.dropped.Collect(ch)
}

func (e *Exporter) run(p part, s *runState, ch chan<- prometheus.Metric) {
	start := e.now()
	b := newBatch()
	err := safeUpdate(p, s, b)
	if err == nil {
		err = b.err
	}
	success := 0.0
	if err == nil {
		success = 1
		for _, m := range b.metrics {
			ch <- m
		}
		for reason, n := range b.drops {
			e.dropped.WithLabelValues(p.name(), reason).Add(float64(n))
		}
	} else {
		e.logger.Warn("collector failed", "collector", p.name(), "err", err)
	}
	ch <- prometheus.MustNewConstMetric(successDesc, prometheus.GaugeValue, success, p.name())
	ch <- prometheus.MustNewConstMetric(durationDesc, prometheus.GaugeValue, e.now().Sub(start).Seconds(), p.name())
}

// polledPart is a part together with the result of its latest poll.
type polledPart struct {
	part
	interval time.Duration

	mu          sync.Mutex
	ran         bool
	success     bool
	duration    float64
	metrics     []prometheus.Metric
	lastSuccess time.Time
}

func newPolledPart(p part, interval time.Duration) *polledPart {
	return &polledPart{part: p, interval: interval}
}

// collect emits the latest poll's result: its series only if it succeeded.
func (p *polledPart) collect(ch chan<- prometheus.Metric) {
	p.mu.Lock()
	ran, success, duration, metrics, last := p.ran, p.success, p.duration, p.metrics, p.lastSuccess
	p.mu.Unlock()
	for _, m := range metrics {
		ch <- m
	}
	ch <- prometheus.MustNewConstMetric(successDesc, prometheus.GaugeValue, boolFloat(success), p.name())
	if ran {
		ch <- prometheus.MustNewConstMetric(durationDesc, prometheus.GaugeValue, duration, p.name())
	}
	lastTS := 0.0
	if !last.IsZero() {
		lastTS = unixSeconds(last)
	}
	ch <- prometheus.MustNewConstMetric(lastSuccessDesc, prometheus.GaugeValue, lastTS, p.name())
	ch <- prometheus.MustNewConstMetric(pollIntervalDesc, prometheus.GaugeValue, p.interval.Seconds(), p.name())
}

func realTicker(d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTicker(d)
	return t.C, t.Stop
}

func safeUpdate(p part, s *runState, b *batch) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return p.update(s, b)
}

// runState is what one run of a part gets. api is nil for a live part, so a
// scrape cannot reach the Supervisor. core holds the last /core/info that
// core_info read, which the per-scrape Core probe dials.
type runState struct {
	ctx    context.Context
	api    Getter
	core   *atomic.Pointer[supervisor.CoreInfo]
	logger *slog.Logger
}

// batch buffers a part's metrics so that nothing is emitted unless the whole
// part succeeds. A repeated (desc, labels) pair is ignored rather than
// failing the scrape; it can only arise when sanitising makes two external
// values equal.
type batch struct {
	metrics []prometheus.Metric
	seen    map[seriesKey]struct{}
	drops   map[string]int
	err     error
}

type seriesKey struct {
	desc   *prometheus.Desc
	labels string
}

func newBatch() *batch {
	return &batch{seen: map[seriesKey]struct{}{}, drops: map[string]int{}}
}

func (b *batch) add(desc *prometheus.Desc, vt prometheus.ValueType, v float64, labels ...string) {
	if b.err != nil {
		return
	}
	k := seriesKey{desc: desc, labels: strings.Join(labels, "\xff")}
	if _, dup := b.seen[k]; dup {
		return
	}
	b.seen[k] = struct{}{}
	m, err := prometheus.NewConstMetric(desc, vt, v, labels...)
	if err != nil {
		b.err = err
		return
	}
	b.metrics = append(b.metrics, m)
}

func (b *batch) gauge(desc *prometheus.Desc, v float64, labels ...string) {
	b.add(desc, prometheus.GaugeValue, v, labels...)
}

func (b *batch) drop(reason string, n int) {
	if n > 0 {
		b.drops[reason] += n
	}
}

func boolFloat(v bool) float64 {
	if v {
		return 1
	}
	return 0
}
