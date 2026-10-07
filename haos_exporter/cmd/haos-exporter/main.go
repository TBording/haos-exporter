// Command haos-exporter is a Prometheus exporter for Home Assistant OS, run
// as a Home Assistant app.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	"github.com/prometheus/exporter-toolkit/web/kingpinflag"

	"github.com/TBording/haos-exporter/haos_exporter/internal/collector"
	"github.com/TBording/haos-exporter/haos_exporter/internal/options"
	"github.com/TBording/haos-exporter/haos_exporter/internal/selfcheck"
	"github.com/TBording/haos-exporter/haos_exporter/internal/supervisor"
	"github.com/TBording/haos-exporter/haos_exporter/internal/tlsfiles"
	"github.com/TBording/haos-exporter/haos_exporter/internal/webconfig"
)

const (
	metricsPath     = "/metrics"
	scrapeTimeout   = 9 * time.Second
	shutdownTimeout = 5 * time.Second
	docsHint        = "set basic_auth_password_hash in the app configuration; see DOCS.md for how to generate a bcrypt hash"
)

func main() {
	// The binary is PID 1 (init: false), so it handles SIGTERM itself.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	code := run(ctx, os.Args[1:], os.Getenv, os.Stderr)
	stop()
	os.Exit(code)
}

// run is the exporter; it returns the exit code once ctx is done or the
// server fails.
func run(ctx context.Context, args []string, getenv func(string) string, stderr io.Writer) int {
	app := kingpin.New("haos-exporter", "Prometheus exporter for Home Assistant OS, run as a Home Assistant app.")
	app.Version(version.Print("haos-exporter"))
	app.HelpFlag.Short('h')
	webFlags := kingpinflag.AddFlags(app, ":9100")
	// The web config is generated from the app options; a user-supplied one
	// could drop basic auth, so the toolkit's flag is hidden and refused.
	app.GetFlag("web.config.file").Hidden()
	var (
		supervisorURL = app.Flag("supervisor.url", "Supervisor API base URL.").
				Default("http://supervisor").String()
		tokenEnv = app.Flag("supervisor.token-env", "Name of the environment variable that holds the Supervisor API token.").
				Default("SUPERVISOR_TOKEN").String()
		procPath = app.Flag("path.proc", "procfs mount point.").
				Default("/proc").String()
		dataPath = app.Flag("path.data", "The app's data directory; its filesystem is reported as the data partition.").
				Default("/data").String()
		tlsDir = app.Flag("path.tls", "The app's config folder, holding server.crt and server.key (tls_mode: provided) and client-ca.crt (tls_client_auth).").
			Default(tlsfiles.DefaultDir).String()
		configDir = app.Flag("web.config-dir", "Directory for the generated web config file (mode 0600).").
				Default("/tmp").String()
		optionsFile = app.Flag("options.file", "Read the app options JSON object from this file instead of the Supervisor (for running outside Home Assistant).").
				String()
		logLevelSet bool
		logLevel    = app.Flag("log.level", "Log level; overrides the log_level app option when given.").
				Default(options.DefaultLogLevel).IsSetByUser(&logLevelSet).Enum("debug", "info", "warn", "error")
	)
	app.ErrorWriter(stderr)
	app.UsageWriter(stderr)
	if _, err := app.Parse(args); err != nil {
		fmt.Fprintf(stderr, "haos-exporter: %v\n", err)
		return 2
	}

	level := new(slog.LevelVar)
	if l, err := options.ParseLogLevel(*logLevel); err == nil {
		level.Set(l)
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))
	logger.Info("starting haos-exporter", "version", version.Version, "revision", version.GetRevision())

	if *webFlags.WebConfigFile != "" {
		logger.Error("--web.config.file is not supported: the web config is generated from the app options")
		return 1
	}
	token := getenv(*tokenEnv)
	if token == "" {
		logger.Error("Supervisor token is not set", "env", *tokenEnv)
		return 1
	}
	client, err := supervisor.New(*supervisorURL, token)
	if err != nil {
		logger.Error("invalid Supervisor client configuration", "err", err)
		return 1
	}

	var opts options.Options
	if *optionsFile != "" {
		opts, err = options.FromFile(*optionsFile)
	} else {
		opts, err = options.FromSupervisor(ctx, client)
	}
	if errors.Is(err, options.ErrNoPasswordHash) {
		logger.Error("refusing to serve without basic auth: " + docsHint)
		return 1
	}
	if err != nil {
		logger.Error("invalid app options", "err", err)
		return 1
	}
	if !logLevelSet {
		if l, err := options.ParseLogLevel(opts.LogLevel); err == nil {
			level.Set(l)
		}
	}
	logger.Info("app options loaded", "options", opts)
	if opts.TLSMode == options.TLSProvided {
		if err := tlsfiles.CheckServer(*tlsDir, time.Now()); err != nil {
			logger.Error("refusing to start: tls_mode is provided, but the server certificate cannot be served", "err", err)
			return 1
		}
	}
	if opts.TLSClientAuth {
		if err := tlsfiles.CheckClientCA(*tlsDir); err != nil {
			logger.Error("refusing to start: tls_client_auth is on, but client-ca.crt cannot be used", "err", err)
			return 1
		}
	}

	results := selfcheck.Run(ctx, selfcheck.Config{ProcPath: *procPath, ShmPath: "/dev/shm", Supervisor: client})
	for _, r := range results {
		if r.Passed {
			logger.Info("security check passed", "check", r.Check, "detail", r.Detail)
		} else {
			logger.Warn("security check failed", "check", r.Check, "detail", r.Detail)
		}
	}

	exporter, err := collector.New(collector.Config{
		Logger:     logger,
		Supervisor: client,
		CoreProbe:  collector.NewCoreProbe(collector.DefaultCoreProbeTimeout),
		Host:       &collector.HostConfig{ProcPath: *procPath, DataPath: *dataPath},
		TLS:        &collector.TLSConfig{Dir: *tlsDir, Server: opts.TLSMode == options.TLSProvided, ClientCA: opts.TLSClientAuth},
	})
	if err != nil {
		logger.Error("creating collectors failed", "err", err)
		return 1
	}
	// Poll the Supervisor once before listening, so that the first scrape
	// already has data; from here on scrapes never call the Supervisor.
	exporter.Start(ctx)
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		buildInfo(),
		tlsInfo(opts),
		selfcheck.Metric(results),
		exporter,
	)

	wc := webconfig.Config{
		Username:     opts.BasicAuthUsername,
		PasswordHash: opts.BasicAuthPasswordHash,
		TLS:          opts.TLSMode == options.TLSSelfSigned,
	}
	if wc.TLS {
		wc.DNSNames = certNames(ctx, client, logger)
	}
	if opts.TLSMode == options.TLSProvided {
		wc.CertFile = filepath.Join(*tlsDir, tlsfiles.ServerCertFile)
		wc.KeyFile = filepath.Join(*tlsDir, tlsfiles.ServerKeyFile)
	}
	if opts.TLSClientAuth {
		wc.ClientCAFile = filepath.Join(*tlsDir, tlsfiles.ClientCAFile)
	}
	path, err := webconfig.Write(*configDir, wc, time.Now())
	if err != nil {
		logger.Error("writing web config failed", "err", err)
		return 1
	}
	defer os.Remove(path)
	*webFlags.WebConfigFile = path

	mux := http.NewServeMux()
	mux.Handle(metricsPath, promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		ErrorLog:            slog.NewLogLogger(logger.Handler(), slog.LevelError),
		ErrorHandling:       promhttp.ContinueOnError,
		MaxRequestsInFlight: 2,
		Timeout:             scrapeTimeout,
		Registry:            reg,
	}))
	srv := &http.Server{
		Handler:           mux,
		ErrorLog:          serverErrorLog(logger),
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      scrapeTimeout + 5*time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	errc := make(chan error, 1)
	go func() { errc <- web.ListenAndServe(srv, webFlags, logger) }()
	select {
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server failed", "err", err)
			return 1
		}
	case <-ctx.Done():
		logger.Info("shutting down")
		sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(sctx); err != nil {
			logger.Warn("graceful shutdown incomplete", "err", err)
		}
		// Serve returns as soon as Shutdown starts; wait for it before the
		// deferred removal of the web config.
		<-errc
	}
	return 0
}

// buildInfo is haos_exporter_build_info with exactly the labels the design
// lists. The values are set at link time through
// github.com/prometheus/common/version.
func buildInfo() prometheus.Collector {
	g := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "haos_exporter",
		Name:      "build_info",
		Help:      "Build information; the value is always 1.",
		ConstLabels: prometheus.Labels{
			"version":   version.Version,
			"revision":  version.GetRevision(),
			"goversion": version.GoVersion,
		},
	})
	g.Set(1)
	return g
}

// tlsInfo is haos_exporter_tls_info: the TLS mode and whether client
// certificates are required.
func tlsInfo(opts options.Options) prometheus.Collector {
	g := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "haos_exporter",
		Name:      "tls_info",
		Help:      "The TLS configuration in use; the value is always 1.",
		ConstLabels: prometheus.Labels{
			"mode":        opts.TLSMode,
			"client_auth": strconv.FormatBool(opts.TLSClientAuth),
		},
	})
	g.Set(1)
	return g
}

// serverErrorLog is the http.Server error log. The Supervisor watchdog
// (tcp://[HOST]:[PORT:9100]) opens a connection to the port every 120 s and
// closes it without a TLS handshake, which net/http logs as "http: TLS
// handshake error from <addr>: EOF". That line, and a peer resetting the
// connection during the handshake, are logged at debug; every other server
// error stays at warn.
func serverErrorLog(logger *slog.Logger) *log.Logger {
	return log.New(serverLogWriter{logger}, "", 0)
}

type serverLogWriter struct{ logger *slog.Logger }

func (w serverLogWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSuffix(string(p), "\n")
	level := slog.LevelWarn
	if handshakeHangup(msg) {
		level = slog.LevelDebug
	}
	w.logger.Log(context.Background(), level, msg)
	return len(p), nil
}

// handshakeHangup reports whether msg is net/http's line for a client that
// went away during the TLS handshake.
func handshakeHangup(msg string) bool {
	return strings.HasPrefix(msg, "http: TLS handshake error from ") &&
		(strings.HasSuffix(msg, ": EOF") || strings.HasSuffix(msg, ": connection reset by peer"))
}

// certNames returns the host's names for the self-signed certificate's SAN,
// read once from /host/info. The scraper does not verify the certificate,
// so a failure here only costs the SAN.
func certNames(ctx context.Context, client *supervisor.Client, logger *slog.Logger) []string {
	var info supervisor.HostInfo
	if err := client.Get(ctx, supervisor.PathHostInfo, &info); err != nil {
		logger.Warn("host name unavailable for the certificate", "err", err)
		return nil
	}
	if info.Hostname == "" {
		return nil
	}
	return []string{info.Hostname, info.Hostname + ".local"}
}
