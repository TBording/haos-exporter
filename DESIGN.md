# haos-exporter design

A Prometheus exporter for Home Assistant OS, shipped as a Home Assistant app
(add-on). It reports host health, Supervisor state, updates, apps and backups
from **one unprivileged container**: protection mode on, a custom AppArmor
profile, non-root, and the lowest Supervisor API role.

Every decision below was measured against Supervisor `2026.09.2`, HAOS 18.3
(amd64) and Core 2026.9.x. Where a claim rests on Supervisor source it cites
`<file>:<line>` at that tag.

## Goals and non-goals

In scope: host CPU/memory/load/boot time, the data partition's free space,
Supervisor health and resolution-center state, OS/Supervisor/Core versions and
pending updates, per-app state and pending updates, backup count/size/age, and
the exporter's own health.

Out of scope:

- Home Assistant **entity** states. The first-party `prometheus:` integration
  already exports them.
- Per-container CPU/memory for Core, Supervisor and apps — see
  [Why role `default`](#why-role-default). This is the one goal deliberately
  dropped.
- Host network counters. A non-host-network container only sees its own
  `eth0`; the hypervisor already exports the VM's NIC counters. Adding
  `host_network` for data another layer has would cost a privilege and a
  security-rating point.
- Boot partition usage. `/mnt/boot` is not visible to an app container
  (only its size, via `/sys/block`).

## Why role `default`

The Supervisor authorizes an app token by matching the **request path only**;
`request.method` is never consulted (`supervisor/api/middleware/security.py`,
`token_validation`, lines 316-390). So there is no read-only role: every role
above `default` grants the write routes under its prefixes.

| Role | Adds (read) | Also grants (write) |
|---|---|---|
| `default` | every `/<x>/info` route | nothing a literal `.../info` path reaches in practice |
| `homeassistant` | `/core/stats` | `/core/{stop,restart,update}` |
| `backup` | `/backups` | backup restore and delete |
| `manager` | all `*/stats`, `/addons`, `/available_updates`, `/store` | host reboot/shutdown, OS/Supervisor updates, app stop/uninstall/options, backup restore, **store repository add and app install** |

`manager` is effectively root-equivalent. It can `POST /store/repositories`
(`api/__init__.py:1094`, matched by `/store.*` in the manager regex) and
`POST /store/addons/{app}/install` (`api/__init__.py:1021`). Install checks only
architecture, machine and version (`apps/model.py:733`), and a container's
capabilities come straight from the app manifest's `privileged` list with no
protection-mode check (`docker/app.py:373-389`). A token that can add a
repository and install from it can therefore start an app holding `SYS_MODULE`.

A network-facing process should not hold that token. Everything in scope is
reachable with `default`:

| Data | Endpoint | Role |
|---|---|---|
| Hostname, kernel, disk life time | `/host/info` | default |
| OS version, update, boot slots | `/os/info` | default |
| Core version, update, IP/port | `/core/info` | default |
| Supervisor health, supported, flags, **app list with state/version/update** | `/supervisor/info` | default |
| Resolution center | `/resolution/info` | default |
| Backups | `/backups/info` | default |
| Own options | `/addons/self/options/config` | any app token (bypass list) |

Switching to `manager` later is a one-line manifest change plus a stats
collector; the permission table in the README must change with it.

**Known future break, and the plan.** The app list in v1 `/supervisor/info`
is marked deprecated. In Supervisor 2026.09.3 the v1 endpoint still returns
it whether or not the `supervisor_v2_api` feature flag is on
(`api/supervisor.py`, `info_v1`). The flag only mounts the `/v2` API, whose
`/v2/supervisor/info` has no app list and whose `/v2/apps` needs `manager`.
The plan:

- **The exporter stays on role `default`.** It will not move to `manager` to
  keep the app metrics: `manager` is root-equivalent (above). Losing
  `haos_app_*` is the accepted cost.
- **The break is reported, not silent.** When a release drops the field (or
  sends it as `null`), `/supervisor/info` still parses, and the rest of the
  `supervisor_info` collector keeps working: Supervisor version, health and
  feature flags. But `haos_supervisor_app_list_present` drops to 0, every
  `haos_app_*` series and `haos_updates_pending{type="app"}` are left out
  rather than reported as zero, and each poll logs an ERROR naming the
  cause. An empty list (`[]`) is still a list: it reports 1 and a pending
  count of 0.
- **Watch for it:**
  - Alert on `haos_supervisor_app_list_present == 0`.
  - Alert on `haos_supervisor_feature_flag{flag="supervisor_v2_api"} == 1`
    as the early sign. DOCS.md has both expressions.
- **When either fires,** re-measure against that release's Supervisor
  source. If a role below `manager` can read the app list there, use it.
  Otherwise, drop the app metrics in a release and say so in the changelog.

## Data sources

### The data partition: `statfs("/data")`

Every app's `/data` is a bind mount of a directory on the data partition
(`config.py:281-283`, `docker/app.py:440-448`). The Supervisor's own disk
figures are `shutil.disk_usage("/data")` inside its container, rounded to
0.1 GiB (`host/info.py:115-134`, `hardware/disk.py:59-88`). A `statfs` on the
app's `/data` sees the same filesystem, so it reproduces those figures at byte
precision. Measured on a live install: `f_blocks × f_frsize`,
`(f_blocks − f_bfree) × f_frsize` and `f_bavail × f_frsize` matched
`ha host info` total/used/free in three paired runs.

Exported in node_exporter's shape so existing dashboards and rules can select
it:

```
node_filesystem_size_bytes{device="/dev/sda8",fstype="ext4",mountpoint="/mnt/data"}
node_filesystem_free_bytes{...}    # f_bfree
node_filesystem_avail_bytes{...}   # f_bavail — what the Supervisor calls "free"
```

`mountpoint` is the host path, not the container path, because that is what an
operator recognises. `device` and `fstype` come from `/proc/self/mountinfo`
for the `/data` mount. `avail` is the value to alert on: the Supervisor blocks
updates, backups and app installs when its "free" (`f_bavail`) drops below
2 GiB (`resolution/const.py:14`, `jobs/decorator.py:416-426`).

### Host CPU, memory, load, boot time: `/proc`

`/proc/stat`, `/proc/meminfo` and `/proc/loadavg` are kernel-global, not
PID-namespaced, so an app without `host_pid` reads the VM's values. Measured:
the container's `MemTotal` equals the hypervisor's view of the guest, and
`/proc/loadavg` counts the whole host's tasks. Exported with node_exporter's
names:

```
node_cpu_seconds_total{cpu,mode}
node_load1 node_load5 node_load15
node_memory_{MemTotal,MemFree,MemAvailable,Buffers,Cached,SwapTotal,SwapFree}_bytes
node_boot_time_seconds     # /proc/stat btime
node_time_seconds          # wall clock at scrape
node_uname_info{nodename,release,machine,sysname}
```

`nodename` is the host's name from `/host/info`, **not** the container
hostname, which is the app slug. `release` is the kernel from `/host/info`.

### Disk IO and pressure: `/proc/diskstats`, `/proc/pressure/*`

Both are kernel-global too; measured through an unprivileged app, the
container sees full counters for `sda` and every partition, and
`/proc/pressure/*` differs from the container's own cgroup pressure, so it is
system-wide. They are separate collectors (`disk`, `pressure`), so a missing
or unreadable file costs only its own series. Names and units follow
node_exporter v1.12.1:

```
node_disk_{reads,writes}_completed_total{device}
node_disk_{read,written}_bytes_total{device}          # sectors × 512
node_disk_{read,write,io}_time_seconds_total{device}  # ms ticks / 1000
node_disk_io_time_weighted_seconds_total{device}
node_disk_io_now{device}
node_disk_{reads,writes}_merged_total{device}
node_disk_{discards_completed,discards_merged,discarded_sectors}_total{device}  # kernel >= 4.18
node_disk_discard_time_seconds_total{device}
node_disk_flush_requests{,_time_seconds}_total{device}                         # kernel >= 5.5
node_pressure_{cpu,io,memory}_waiting_seconds_total   # "some" line
node_pressure_{io,memory,irq}_stalled_seconds_total   # "full" line
```

**The device filter keeps partitions, unlike node_exporter's default.** The
hypervisor already has the VM's whole-disk IO, and its counters span guest
reboots; only the guest can split IO by partition (the data partition against
the rest of the disk). Kept: whole disks and partitions of `sd*`, `vd*`,
`hd*`, `xvd*`, `nvme*n*`, `mmcblk*`. Dropped: `zram`, `loop`, device-mapper,
md and anything else. A field is emitted only if the kernel reports it.

For pressure, a missing file is skipped (a kernel without PSI, or `irq`
without IRQ time accounting), and PSI compiled in but disabled at boot yields
no series; neither fails the collector. Any other read error does: a
permission error is what a missing AppArmor rule looks like, and it must not
read as "no PSI".

### Supervisor API

GET only, six paths: `/host/info`, `/os/info`, `/core/info`,
`/supervisor/info`, `/resolution/info`, `/backups/info`. Each takes 1–3 ms.

**They are polled in the background, not fetched on scrape.** Each call
writes one INFO `"<path> access from <app>"` line to the Supervisor log at the
default `logging: info` (`api/middleware/security.py:378` at 2026.09.2), and
nothing an app can do lowers that line's level. Fetch-on-scrape therefore tied
the Supervisor's log volume to the scrape interval. Measured on a live install
at a 60 s scrape: 6 lines per scrape, about 8,570 a day, which was 52% of
everything the Supervisor logged. A 15 s scrape would have quadrupled it.

| Path | Poll interval | Why |
|---|---|---|
| `/supervisor/info`, `/resolution/info` | 60 s | health, app state and resolution issues change by themselves |
| `/host/info`, `/os/info`, `/core/info`, `/backups/info` | 5 min | versions, pending updates, backups and host identity |

That is 2 × 1,440 + 4 × 288 ≈ 4,000 lines a day, whatever the scrape
interval. The first poll of every path runs at start, before the listener
opens; a scrape only replays each collector's latest result, so it never
waits on the Supervisor.

This departs from the usual exporter model, where a scrape fetches. The usual
model is right when fetching is free; here every fetch is written to another
component's log, and the Supervisor-backed values do not change on a scrape's
timescale. The host collectors, which cost nothing upstream, stay per scrape,
so the scrape interval still sets their resolution.

Container stats endpoints are not used: stats for Core, the Supervisor and
other apps need `manager` (Core's also `homeassistant`), and each call blocks
~1–2 s while Docker samples. Only the app's own `/addons/self/stats` is open
to every app token, and it is not in scope.

### Core liveness

`/core/info` gives Core's IP and port on the internal network. The exporter
sends `GET /manifest.json` there (served by the frontend without auth) on
every scrape, using the address from the last successful `/core/info` poll.
Any HTTP response is "up"; a connection error or timeout is "down". No token
and no `homeassistant_api` are involved, and no Supervisor log line is
written.

The probe must never touch an authenticated path such as `/api/`: Core's ban
middleware treats every 401 as a failed login, logs a warning and raises a
"Login attempt failed" notification — once per scrape.

## Metrics

All `haos_*` series. Label values that come from outside this code (names,
versions, reasons) are sanitised: valid UTF-8, printable characters only,
truncated to 128 runes. App slugs must match `^[-_.A-Za-z0-9]{1,64}$`
(the Supervisor's own slug pattern) or the app is skipped and counted.

| Metric | Labels | Source |
|---|---|---|
| `haos_component_version_info` | `component` (core, supervisor, os), `version`, `version_latest` | `*/info` |
| `haos_component_update_available` | `component` | `*/info` |
| `haos_updates_pending` | `type` (core, supervisor, os, app) | derived |
| `haos_supervisor_healthy` | | `/supervisor/info` |
| `haos_supervisor_supported` | | `/supervisor/info` |
| `haos_supervisor_feature_flag` | `flag` | `/supervisor/info` |
| `haos_supervisor_app_list_present` | | `/supervisor/info`: 1 while it carries the app list; 0 when the field is missing, and then no app series and no `haos_updates_pending{type="app"}` |
| `haos_os_boot_slot_info` | `slot`, `state`, `status`, `version` | `/os/info` |
| `haos_app_info` | `slug`, `name`, `version`, `version_latest`, `repository` | `/supervisor/info` |
| `haos_app_state` | `slug`, `state` (started, stopped, startup, error, unknown) | StateSet: 1 for the current state, 0 for the rest |
| `haos_app_update_available` | `slug` | `/supervisor/info` |
| `haos_core_up` | | Core `GET /manifest.json` probe (unauthenticated) |
| `haos_resolution_unhealthy` | `reason` | `/resolution/info` |
| `haos_resolution_unsupported` | `reason` | `/resolution/info` |
| `haos_resolution_issues` | `type`, `context` | count per pair |
| `haos_resolution_suggestions` | `type`, `context` | count per pair |
| `haos_backups` | `type` (full, partial, other) | count; always emitted for full and partial |
| `haos_backups_size_bytes` | `type` | sum of `size_bytes` |
| `haos_backup_latest_timestamp_seconds` | `type` | newest `date`; absent when count is 0 |
| `haos_host_disk_life_time_used_ratio` | | `/host/info`; absent when the Supervisor reports `null` |
| `haos_exporter_collector_success` | `collector` | 0 on any error in that collector's last run (its last poll, for a Supervisor collector) |
| `haos_exporter_collector_duration_seconds` | `collector` | |
| `haos_exporter_collector_last_success_timestamp_seconds` | `collector` | Supervisor collectors only; 0 until the first success |
| `haos_exporter_collector_poll_interval_seconds` | `collector` | Supervisor collectors only |
| `haos_exporter_series_dropped_total` | `collector`, `reason` | counter for caps and invalid slugs |
| `haos_exporter_security_check` | `check` | see [Self-check](#startup-self-check) |
| `haos_exporter_build_info` | `version`, `revision`, `goversion` | |
| `haos_exporter_tls_info` | `mode`, `client_auth` | always 1; `mode` is the serving mode |
| `haos_exporter_tls_certificate_expiry_timestamp_seconds` | `cert` (server, client_ca) | `provided` mode and `tls_client_auth` only; `client_ca` is the latest `NotAfter` in `client-ca.crt` |

Plus the standard `go_*` and `process_*` collectors.

Never labels: resolution `uuid`s, backup names or slugs, app descriptions or
options, IP addresses, tokens.

Caps: 256 apps; 64 distinct resolution `(type, context)` pairs per kind; 64
series each for feature flags, boot slots, unhealthy reasons and unsupported
reasons; 64 disk devices. The feature-flag cap always keeps `supervisor_v2_api` (see
[Known future break](#why-role-default)). Over the cap, the remainder is
dropped and counted in `haos_exporter_series_dropped_total`.

## Failure behaviour

- Every Supervisor call has a 5 s timeout and a 1 MiB response cap; a larger
  body is an error, not a truncated parse.
- The host collector and the Core probe run concurrently at scrape time;
  the Supervisor collectors each run in their own background poller. A
  collector whose last run failed sets its `haos_exporter_collector_success`
  to 0 and emits none of its own series: a failed poll does not keep serving
  the previous poll's values as if they were current. It still emits its
  duration and, for a Supervisor collector, its last-success timestamp and
  poll interval. The other collectors and the HTTP response are unaffected.
  The process never exits because of an upstream error.
- A stuck or failing poller is detectable: alert when
  `time() - haos_exporter_collector_last_success_timestamp_seconds` exceeds a
  few multiples of `haos_exporter_collector_poll_interval_seconds`. A
  timestamp of 0 (never succeeded) trips that at once.
- Responses are decoded into structs holding **only** the fields above. Fields
  that can carry secrets (`options`, `ingress_entry`, `ingress_url`) are never
  decoded, so they can never reach a label or a log line.
- `SUPERVISOR_TOKEN` is read once from the environment and only ever placed in
  the `Authorization` header. It is never logged, and error messages carry the
  request path, not the URL with headers.

## The metrics endpoint

Listens on `:9100` (published through the manifest's `ports`, no
`host_network`). Served by `prometheus/exporter-toolkit`:

- **Basic auth is mandatory.** The bcrypt hash comes from the app option
  `basic_auth_password_hash`; with no hash set the exporter logs why and exits
  non-zero rather than serve unauthenticated.
- **TLS by default.** `tls_mode: self_signed` generates an ECDSA P-256
  certificate in memory at start. It protects the credential from passive
  capture on the LAN; it does not authenticate the server (the scraper sets
  `insecure_skip_verify`), and it changes on every restart. `tls_mode:
  provided` serves operator-supplied files and lets the scraper pin the
  certificate; see [Verified TLS](#verified-tls).
  `tls_mode: off` is the explicit opt-in to plain HTTP.
- The toolkit reads its web-config file, so the exporter writes one to `/tmp`
  (tmpfs, mode 0600) at start. Nothing is written anywhere else.
- `promhttp` runs with `MaxRequestsInFlight: 2` and a 9 s handler timeout.
- No toolkit `rate_limit`. It is one token bucket for all clients, checked
  before authentication, so any client without credentials that sends
  requests faster than the refill rate keeps the bucket empty. Measured
  against exporter-toolkit v0.20.0 with an interval of 1 s and a burst of 10:
  after 15 credential-less requests had drained the burst, a client sending 2
  requests/s turned 5 of 5 authenticated scrapes into 429; without the limit
  all 5 returned 200. Without the limit, only a large flood of uncached wrong
  passwords delays scrapes; see the README's residual risks.

## Runtime confinement

What the manifest can and cannot express, per Supervisor `2026.09.2`:

| Requirement | How it is met |
|---|---|
| Protection mode on | Default; nothing requested needs it off |
| No `docker_api`, `full_access`, `privileged`, `host_pid`, `host_network` | Not requested |
| Least API privilege | `hassio_api: true`, `hassio_role: default`; no `homeassistant_api`, no `auth_api` |
| Non-root | Image `USER 65532:65532` (distroless `nonroot`); the Supervisor sets no `User`, so the image's wins |
| Read-only root filesystem | **Not expressible** — the Supervisor never sets `ReadonlyRootfs`. Met by DAC (non-root, root-owned image files) plus AppArmor denying writes outside `/tmp` and `/dev/null` |
| No capabilities | **Not expressible** — Supervisor 2026.09.2 sets no `CapDrop`; 2026.09.3 drops `NET_RAW` and `AUDIT_WRITE`/`MKNOD`/`SETFCAP` only while the feature flags `app_drop_net_raw` / `app_reduced_capabilities` are on (default off). A non-root process has no effective capabilities; AppArmor grants none |
| Seccomp | The Supervisor forces `seccomp=unconfined` for every app (`docker/interface.py:202-206`). AppArmor is the only mandatory-access-control layer |
| AppArmor | Custom `apparmor.txt`, enforce mode. The Supervisor renames the profile to the full slug and loads it on install/update only — **bump `version` whenever it changes** |
| `/data/options.json` | Root-owned 0600, unreadable by uid 65532. Options come from `GET /addons/self/options/config` instead |
| Init | `init: false`: the Go binary is PID 1 and handles `SIGTERM` itself |

### Startup self-check

At start the exporter logs, and reports as
`haos_exporter_security_check{check}` (1 = as intended):

| `check` | Pass condition |
|---|---|
| `nonroot` | effective uid ≠ 0 |
| `no_capabilities` | `CapEff` in `/proc/self/status` is 0 |
| `apparmor_enforced` | `/proc/self/attr/current` names a profile in `(enforce)` mode |
| `apparmor_blocks_write` | creating a file in `/dev/shm` fails with a permission error (`EACCES` or `EPERM`); any other error, such as a missing `/dev/shm`, fails the check. `/dev/shm` is a world-writable tmpfs, so DAC allows it — only AppArmor can make it fail. A non-root write to `/` would fail on permissions alone and prove nothing about the profile |
| `role_least_privilege` | `GET /addons` (a `manager`-only path) returns 403 |

A failed check is logged as a warning; the exporter keeps serving. The checks
are diagnostics, not proof. `apparmor_enforced` accepts any profile in
enforce mode, not this app's by name. `apparmor_blocks_write` tests one
denial, not the whole profile. `role_least_privilege` also passes for the
`homeassistant` and `backup` roles, which cannot reach `/addons` either.
`ci/check_manifest.py` pins `hassio_role: default`.

### Verified TLS

`tls_mode: provided` and `tls_client_auth` are designed in
[`docs/superpowers/specs/2026-10-03-verified-tls-design.md`](docs/superpowers/specs/2026-10-03-verified-tls-design.md).
In short:

- **Where the key lives.** The exporter cannot write a key anywhere that
  persists (it is uid 65532, and `/data` is root's), so the operator places
  the key in the app's read-only `app_config` folder. `backup_exclude` keeps
  it out of backups.
- **Rotation.** exporter-toolkit re-reads the files on every connection, so
  both certificates rotate without a restart.
- **Failing closed.** The exporter refuses to start on a missing,
  mismatched, expired or over-readable pair.

## Build and distribution

- Multi-stage `Dockerfile`: `golang` (Alpine) builder, `CGO_ENABLED=0`,
  `-trimpath`; final stage `gcr.io/distroless/static-debian13:nonroot`. Both
  pinned by digest.
- The Go module lives inside the app folder, so the folder is a complete build
  context: the Supervisor builds it locally when the manifest has no `image:`.
- Until 2026-10-07 (private phase): installed as a local app from
  `/local_apps`, built on the device.
- Since 0.4.0: `.github/workflows/release.yml` publishes the multi-arch image
  to GHCR, signed and attested, and the manifest's `image:` points at it. The
  package is public, so the Supervisor holds no registry credentials.
