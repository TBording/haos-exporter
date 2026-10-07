package collector

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/TBording/haos-exporter/haos_exporter/internal/tlsfiles"
)

// TLSConfig enables the tls collector, which reports when the
// operator-provided certificates expire. It re-reads the files on every
// scrape, so a rotation shows up without a restart.
type TLSConfig struct {
	// Dir is the config folder holding the files.
	Dir string
	// Server reports server.crt (tls_mode: provided).
	Server bool
	// ClientCA reports client-ca.crt (tls_client_auth).
	ClientCA bool
}

var tlsExpiryDesc = prometheus.NewDesc(
	"haos_exporter_tls_certificate_expiry_timestamp_seconds",
	`When a provided certificate expires, in Unix seconds: cert="server" for server.crt, cert="client_ca" for the latest-expiring certificate in client-ca.crt.`,
	[]string{"cert"}, nil,
)

type tlsPart struct{ cfg TLSConfig }

func (tlsPart) name() string { return collectorTLS }

func (tlsPart) describe(ch chan<- *prometheus.Desc) { ch <- tlsExpiryDesc }

func (p tlsPart) update(_ *runState, b *batch) error {
	if p.cfg.Server {
		t, err := tlsfiles.ServerExpiry(p.cfg.Dir)
		if err != nil {
			return err
		}
		b.gauge(tlsExpiryDesc, unixSeconds(t), "server")
	}
	if p.cfg.ClientCA {
		t, err := tlsfiles.ClientCAExpiry(p.cfg.Dir)
		if err != nil {
			return err
		}
		b.gauge(tlsExpiryDesc, unixSeconds(t), "client_ca")
	}
	return nil
}
