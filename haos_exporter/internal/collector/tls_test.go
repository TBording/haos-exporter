package collector

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/TBording/haos-exporter/haos_exporter/internal/testcerts"
)

const tlsExpiryMetric = "haos_exporter_tls_certificate_expiry_timestamp_seconds"

func tlsExporter(t *testing.T, cfg TLSConfig) *Exporter {
	t.Helper()
	e, err := New(Config{TLS: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestTLSExpiry(t *testing.T) {
	dir := t.TempDir()
	server := testcerts.New(t, testcerts.Server("haos-exporter"))
	testcerts.WriteServer(t, dir, server)
	old := testcerts.Client("prometheus")
	old.NotAfter = time.Now().Add(10 * 24 * time.Hour)
	a, b := testcerts.New(t, old), testcerts.New(t, testcerts.Client("prometheus"))
	testcerts.WriteFile(t, filepath.Join(dir, "client-ca.crt"), append(append([]byte{}, a.CertPEM...), b.CertPEM...), 0o444)

	mfs := collectOnce(t, tlsExporter(t, TLSConfig{Dir: dir, Server: true, ClientCA: true}))
	if successOf(t, mfs, collectorTLS) != 1 {
		t.Fatal("tls collector failed")
	}
	for cert, want := range map[string]time.Time{"server": server.Cert.NotAfter, "client_ca": b.Cert.NotAfter} {
		if v, ok := value(mfs, tlsExpiryMetric, map[string]string{"cert": cert}); !ok || v != unixSeconds(want) {
			t.Errorf("%s expiry = %v (%t), want %v", cert, v, ok, unixSeconds(want))
		}
	}
}

func TestTLSExpiryFollowsRotation(t *testing.T) {
	dir := t.TempDir()
	first := testcerts.New(t, testcerts.Server("haos-exporter"))
	testcerts.WriteServer(t, dir, first)
	e := tlsExporter(t, TLSConfig{Dir: dir, Server: true})
	collectOnce(t, e)
	later := testcerts.Server("haos-exporter")
	later.NotAfter = time.Now().Add(700 * 24 * time.Hour)
	second := testcerts.New(t, later)
	testcerts.WriteServer(t, dir, second)
	mfs := collectOnce(t, e)
	if v, _ := value(mfs, tlsExpiryMetric, map[string]string{"cert": "server"}); v != unixSeconds(second.Cert.NotAfter) {
		t.Fatalf("expiry %v after rotation, want %v", v, unixSeconds(second.Cert.NotAfter))
	}
}

func TestTLSCollectorFailureIsReported(t *testing.T) {
	dir := t.TempDir()
	testcerts.WriteServer(t, dir, testcerts.New(t, testcerts.Server("haos-exporter")))
	e := tlsExporter(t, TLSConfig{Dir: dir, Server: true, ClientCA: true}) // no client-ca.crt
	mfs := collectOnce(t, e)
	if successOf(t, mfs, collectorTLS) != 0 {
		t.Fatal("tls collector succeeded without client-ca.crt")
	}
	if n := countSeries(mfs, tlsExpiryMetric); n != 0 {
		t.Fatalf("%d expiry series emitted by a failed collector", n)
	}
}

func TestTLSCollectorAbsentWithoutProvidedFiles(t *testing.T) {
	for _, cfg := range []*TLSConfig{nil, {Dir: t.TempDir()}} {
		e, err := New(Config{TLS: cfg})
		if err != nil {
			t.Fatal(err)
		}
		mfs := collectOnce(t, e)
		if _, ok := value(mfs, "haos_exporter_collector_success", map[string]string{"collector": collectorTLS}); ok {
			t.Fatalf("tls collector present for %+v", cfg)
		}
	}
}
