package collector

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// ManifestPath is the only path the Core probe requests. The frontend
// serves it without authentication. The probe must never touch an
// authenticated path such as /api/: Core's ban middleware counts every 401
// as a failed login and raises a notification.
const ManifestPath = "/manifest.json"

// DefaultCoreProbeTimeout is short: the probe runs on every scrape and must
// finish well inside the scrape handler's 9 s timeout, and the shortest
// scrape interval in use is 15 s.
const DefaultCoreProbeTimeout = 3 * time.Second

var coreUpDesc = prometheus.NewDesc(namespace+"_core_up",
	"1 if Home Assistant Core answered GET "+ManifestPath+" with any HTTP status, 0 on a connection error or timeout.",
	nil, nil)

// CoreProbe sends an unauthenticated GET /manifest.json to Core.
type CoreProbe struct {
	client  *http.Client
	timeout time.Duration
}

// NewCoreProbe returns a CoreProbe with the given timeout.
func NewCoreProbe(timeout time.Duration) *CoreProbe {
	return &CoreProbe{
		timeout: timeout,
		client: &http.Client{
			Transport: &http.Transport{
				Proxy:             nil,
				DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
				DisableKeepAlives: true,
				// Core's certificate, when it has one, is issued for the
				// user's public name, not for the internal IP the probe
				// dials. The probe sends nothing and trusts nothing it
				// receives beyond "an HTTP response arrived".
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // liveness only, see above
			},
			// Never follow a redirect: it could lead to an authenticated path.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// Probe reports whether Core at ip:port answers HTTP. Any HTTP status is up;
// a connection error or timeout is down. The error is non-nil only for an
// invalid address.
func (p *CoreProbe) Probe(ctx context.Context, ip string, port int, useTLS bool) (bool, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false, errors.New("core ip_address is not an IP address")
	}
	if port < 1 || port > 65535 {
		return false, fmt.Errorf("core port %d is out of range", port)
	}
	u := url.URL{Scheme: "http", Host: net.JoinHostPort(addr.String(), strconv.Itoa(port)), Path: ManifestPath}
	if useTLS {
		u.Scheme = "https"
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return false, errors.New("building core probe request failed")
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return false, nil
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	return true, nil
}

type coreProbePart struct {
	probe Prober
}

func (coreProbePart) name() string { return collectorCoreProbe }

func (coreProbePart) describe(ch chan<- *prometheus.Desc) { ch <- coreUpDesc }

func (p coreProbePart) update(s *runState, b *batch) error {
	info := s.core.Load()
	if info == nil {
		return errors.New("core address unknown: /core/info has not been read successfully yet")
	}
	up, err := p.probe.Probe(s.ctx, info.IPAddress, info.Port, info.SSL)
	if err != nil {
		return err
	}
	b.gauge(coreUpDesc, boolFloat(up))
	return nil
}
