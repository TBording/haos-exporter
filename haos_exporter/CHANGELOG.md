# Changelog

All notable changes to this app are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the app uses
[Semantic Versioning](https://semver.org/).

Bump `version` in `config.yaml` whenever `apparmor.txt` changes: the
Supervisor reloads the AppArmor profile only on install or update.

## [0.4.1] - 2026-10-07

### Changed

- The manifest names the published image, `ghcr.io/tbording/haos-exporter`,
  so the app is installed from this repository and the Supervisor pulls the
  signed image for its platform instead of building it on the device.
- `github.com/prometheus/common` 0.71.0 → 0.72.0.

### Security

- The release build may reach only the network endpoints it needs
  (harden-runner in block mode); a compromised build step cannot reach any
  host outside that list.

## [0.4.0] - 2026-10-07

The first published image: `ghcr.io/tbording/haos-exporter:0.4.0` for amd64
and aarch64, signed with cosign and carrying SLSA provenance and SPDX SBOM
attestations.

### Added

- `tls_mode: provided` serves `server.crt` and `server.key` from the app's
  config folder (`/config`, mapped read-only), so Prometheus can pin the
  certificate and an interceptor can no longer pose as the exporter
  (independent review, finding 1). The exporter refuses to start when the
  pair is missing, mismatched, expired, not yet valid, lacks `serverAuth` or
  a subject alternative name, or when the key is readable by group or
  others.
- `tls_client_auth` requires a client certificate trusted by
  `client-ca.crt`. A client without one is refused at the TLS handshake and
  never reaches the password check.
- `haos_exporter_tls_info{mode,client_auth}` and
  `haos_exporter_tls_certificate_expiry_timestamp_seconds{cert}`, the latter
  from a new `tls` collector that re-reads the files on every scrape.

### Changed

- TLS 1.3 is the minimum version in every TLS mode.
- The manifest maps the app's own config folder read-only and excludes
  `*.key` from backups. After a restore, `provided` mode refuses to start
  until a new server key is generated.
- The AppArmor profile allows exactly three reads under `/config`.

## [0.3.1] - unreleased

### Fixed

- Each local build no longer leaves the Go build cache and module cache on
  the data partition. The builder stage downloads, builds and deletes both
  caches in one step, so the layer the Supervisor keeps holds only the
  binary: about 9-15 MB instead of 274 MB. Each update had
  been costing about 293 MiB of `/mnt/data` that nothing reclaimed.

## [0.3.0] - 2026-09-28

### Added

- Per-disk and per-partition IO from `/proc/diskstats` as `node_disk_*`, in
  node_exporter's names and units. Unlike node_exporter's default, partitions
  are kept; `zram`, `loop` and device-mapper devices are left out; at most 64
  devices.
- Pressure stall information from `/proc/pressure/{cpu,io,memory,irq}` as
  `node_pressure_*`. A missing file is skipped.
- Both are new collectors, `disk` and `pressure`, with their own
  `haos_exporter_collector_success`.

### Changed

- The AppArmor profile allows reading `/proc/diskstats` and
  `/proc/pressure/*`.

## [0.2.0] - 2026-09-28

### Changed

- The Supervisor endpoints are polled in the background instead of on every
  scrape: `/supervisor/info` and `/resolution/info` every 60 s, the other four
  every 5 min. The Supervisor logs each call at INFO, so its log volume from
  this app is now about 4,000 lines a day whatever the scrape interval, down
  from about 8,570 a day at a 60 s scrape. Scrapes make no Supervisor calls
  and never wait on it; the host series and the Core probe stay per scrape.
- `haos_exporter_series_dropped_total` now counts once per poll rather than
  once per scrape.

### Added

- `haos_exporter_collector_last_success_timestamp_seconds{collector}` (0 until
  the first success) and `haos_exporter_collector_poll_interval_seconds{collector}`
  for the Supervisor collectors.

## [0.1.0] - 2026-09-28

First version, installed as a local app.

### Added

- Host metrics from `/proc` in node_exporter's names: CPU, load, memory,
  boot time, uname.
- Data partition size, free and available bytes from `statfs("/data")`.
- Supervisor health, supported state, feature flags and resolution center.
- Core, Supervisor and OS versions and pending updates; OS boot slots.
- Per-app info, state and pending updates (capped at 256 apps).
- Backup count, total size and newest timestamp per type.
- Core liveness through an unauthenticated `GET /manifest.json`.
- Exporter self-metrics and a startup security self-check
  (`haos_exporter_security_check`).
- Mandatory basic auth (bcrypt hash option) and HTTPS with an in-memory
  self-signed certificate by default.

### Security

- Supervisor role `default`; no Home Assistant API, auth API, host network,
  host PID, Docker API, full access, capabilities or device access.
- Custom AppArmor profile in enforce mode; non-root (uid 65532) distroless
  image; `/tmp` tmpfs is the only writable path.
- Bounded label cardinality: at most 256 apps, 64 resolution
  `(type, context)` pairs per kind, and 64 series each for feature flags,
  boot slots and unhealthy and unsupported reasons; the excess is counted in
  `haos_exporter_series_dropped_total`.
