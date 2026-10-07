# haos-exporter

A Prometheus exporter for Home Assistant OS, shipped as a Home Assistant app
(formerly "add-on"). It reports host health, the data partition, Supervisor
state, pending updates, apps and backups from **one unprivileged container**:
protection mode on, the lowest Supervisor API role, a custom AppArmor profile
in enforce mode, and a non-root user. The metrics endpoint requires basic
auth and serves HTTPS by default.

Home Assistant entity states are out of scope; the built-in `prometheus:`
integration exports them.

- [`DESIGN.md`](DESIGN.md): the measured design decisions and the full
  metric list.
- [`haos_exporter/DOCS.md`](haos_exporter/DOCS.md): user documentation,
  options and a Prometheus scrape config.
- [`SECURITY.md`](SECURITY.md): how to report a vulnerability.
- [`docs/public-flip-checklist.md`](docs/public-flip-checklist.md): what must
  happen before this repository becomes public.

## Metrics

Host CPU, memory, load, boot time, per-partition disk IO and pressure stall
information from `/proc`, and data-partition space from `statfs("/data")`,
in node_exporter's metric names; plus `haos_*` series
for the Supervisor, resolution center, versions and updates, apps, backups,
Core liveness and the exporter itself. The full list, with labels, sources,
sanitisation rules and cardinality caps, is in
[DESIGN.md § Metrics](DESIGN.md#metrics).

## Permissions

What the manifest ([`haos_exporter/config.yaml`](haos_exporter/config.yaml))
requests, what it does not, and what each would buy. Security-rating effects
are from the Home Assistant developer docs. CI
([`ci/check_manifest.py`](ci/check_manifest.py)) fails if the manifest holds
any top-level key outside the short list it uses, which covers every "not
requested" key below and any misspelled key. The Supervisor silently drops
unknown keys, so a typo would otherwise go unnoticed.

### Requested

| Manifest entry | What it grants | Why |
|---|---|---|
| `hassio_api: true` | A `SUPERVISOR_TOKEN` for the Supervisor REST API | Six `GET /<x>/info` endpoints, polled every 60 s or 5 min (never per scrape), plus the app's own options |
| `hassio_role: default` | Paths matching `/<x>/info`, plus the routes every app token passes without a role check: this app's own `/addons/self/*` (options, info, stats, restart, uninstall), `/info`, `/services`, `/discovery` and `/auth`. The handlers behind the last three refuse this app, which declares no services, discovery or `auth_api`; only the list of service names at `GET /services` is open | Covers everything in scope; see [DESIGN.md § Why role `default`](DESIGN.md#why-role-default) |
| `ports: 9100/tcp` | Container port 9100 published on the host | Prometheus must reach the exporter; ingress needs a Home Assistant session cookie, which a scraper cannot present |
| `tmpfs: true` | `/tmp` as a tmpfs | The only writable directory; holds the exporter-toolkit web-config file |
| `apparmor: true` + `apparmor.txt` | A custom profile in enforce mode instead of Docker's default | Denies writes outside `/tmp` and `/dev/null`, all capabilities, ptrace, mount and exec; +1 security rating |
| `init: false` | No `docker-init` as PID 1 | The Go binary is PID 1 and handles `SIGTERM`; one less binary to allow in the profile |
| `watchdog: tcp://[HOST]:[PORT:9100]` | The Supervisor restarts the app when the port stops accepting connections | Not a privilege |
| `map: app_config` (read-only) | This app's own config folder at `/config`, which no other app sees unless it maps every app's config folder | `tls_mode: provided` and `tls_client_auth` read `server.crt`, `server.key` and `client-ca.crt` there. The AppArmor profile allows exactly those three reads |
| `backup_exclude: ["*.key"]` | Leaves matching files out of Home Assistant backups | Not a privilege. The server key never enters a backup; after a restore, a new one is generated |

### Not requested

| Manifest entry | What it would buy | Why not |
|---|---|---|
| `hassio_role: homeassistant` | `/core/stats` (Core CPU/memory) | Also grants `/core/{stop,restart,update}` |
| `hassio_role: backup` | `/backups` | Same data as `/backups/info`; also grants backup restore and delete |
| `hassio_role: manager` | All `*/stats` (per-container CPU/memory), `/addons`, `/available_updates`, `/store` | Also grants host reboot/shutdown, OS and Supervisor updates, app stop/uninstall/options, backup restore, and adding a store repository and installing from it, which can start an app holding `SYS_MODULE`. Effectively root. −1 rating |
| `hassio_role: admin` | Everything | Everything. −2 rating |
| `homeassistant_api` | Core's REST API through the Supervisor proxy | Read and change every entity and call any service. Core liveness uses an unauthenticated `GET /manifest.json` instead |
| `auth_api` | Validating Home Assistant user credentials | The exporter checks its own bcrypt credential |
| `host_network` | The host's network namespace and NIC counters | The hypervisor already exports the VM's NIC counters. −1 rating |
| `host_pid` | The host's PID namespace | Per-process host data; `/proc/{stat,meminfo,loadavg}` already show the host. Needs protection mode off. −2 rating |
| `host_ipc`, `host_uts`, `host_dbus` | Host IPC, hostname namespace, host D-Bus (systemd, OS Agent) | Nothing in scope; the hostname comes from `/host/info` |
| `docker_api` | The Docker socket | Per-container stats directly, but it is root on the host. Needs protection mode off. Rating 1 |
| `full_access` | Every host device | Nothing. Needs protection mode off. Rating 1 |
| `privileged` | Extra Linux capabilities | Nothing; no capability is used |
| `devices`, `uart`, `usb`, `gpio`, `video`, `audio`, `udev`, `devicetree`, `kernel_modules`, `realtime` | Hardware access, `SYS_MODULE`, `SYS_NICE` | Nothing |
| `journald` | The host journal, read-only | Log-derived metrics are out of scope |
| Any other `map` type, or `app_config` writable | Bind mounts of `homeassistant_config`, `share`, `backup`, `ssl`, `media` and so on, or write access to `/config` | Nothing; backup sizes come from the API, `/data` is always mounted, and the exporter only reads `/config` |
| `ingress` | A Home Assistant-authenticated web UI. +2 rating | A scraper outside Home Assistant cannot pass ingress authentication |
| Protection mode off | Allows `host_pid`, `docker_api`, `full_access` | None of them is requested |
| `image` | Pulling a prebuilt image from a registry | Not a privilege. Omitted while the repository is private, so the Supervisor builds the image on the device; see the checklist |

### What the manifest cannot express

- **Read-only root filesystem**: the Supervisor never sets `ReadonlyRootfs`.
  The image files are root-owned and the process runs as uid 65532, so DAC
  prevents writes; the AppArmor profile denies writes outside `/tmp` and
  `/dev/null` as well.
- **Dropping capabilities**: Supervisor 2026.09.2 sets no `CapDrop`.
  2026.09.3 drops `NET_RAW`, and `AUDIT_WRITE`, `MKNOD` and `SETFCAP`, only
  while the feature flags `app_drop_net_raw` and `app_reduced_capabilities`
  are on (both default to off; the exporter reports them as
  `haos_supervisor_feature_flag`). There is no manifest key for it either way.
  A non-root process has no effective capabilities, and the profile grants
  none.
- **Seccomp**: the Supervisor runs every app with `seccomp=unconfined`.
  AppArmor is the only mandatory access control layer.
- **`no-new-privileges`**: not set by the Supervisor. The distroless image has
  no setuid binaries, and the profile allows no exec at all.

At start the exporter checks these properties and reports them as
`haos_exporter_security_check{check}`: non-root, no effective capabilities,
AppArmor in enforce mode, AppArmor blocking a write that DAC would allow, and
a `manager`-only Supervisor path refused with 403. These are diagnostics, not
proof: the AppArmor check accepts any profile in enforce mode, the write probe
tests one denial, and the 403 also holds for the `homeassistant` and `backup`
roles. CI pins `hassio_role: default` in the manifest.

## Threat model

### Assets

1. **`SUPERVISOR_TOKEN`** (role `default`). Injected by the Supervisor into
   the environment, where any code running in the process can read it. With
   it, anyone can read every `/<x>/info` endpoint (host, OS, network, hardware
   inventory, app metadata, backups) and, through the app-self paths every
   app token has, read and change this app's own options, read its own stats,
   and stop, restart or uninstall it.
2. **The basic-auth credential**. The password is stored only on the
   Prometheus side, but the exporter receives it with every scrape, and
   exporter-toolkit keeps a hex-encoded copy in memory as part of its
   authentication-cache key. Its bcrypt hash is an app option: the Supervisor
   stores it, writes it to the Supervisor log when that log is at debug level,
   and includes it in Home Assistant backups. The exporter writes it to a
   `0600` web-config file on the `/tmp` tmpfs.
3. **The metrics**. Versions and pending updates tell an attacker which known
   vulnerabilities apply; the app list, backup age and hostname are
   reconnaissance.
4. **The server key** (`tls_mode: provided`). `server.key` in the app's
   config folder, owned by uid 65532 with no group or other bits. It is
   readable by root on the host and by apps that map every app's config
   folder (Terminal & SSH, Studio Code Server, Samba). It is excluded from
   backups and never passes through the app options or the logs. With it,
   an interceptor could pose as the exporter.

### Adversaries and mitigations

| Adversary | Mitigations |
|---|---|
| **LAN attacker** who can reach port 9100 and observe or intercept traffic | Basic auth is mandatory: the Supervisor refuses to start the app while the hash option is unset, and the exporter refuses an empty or malformed hash at start (exit 1), so neither path serves unauthenticated. HTTPS by default with an in-memory ECDSA P-256 certificate, so the password is not visible to passive capture. In `self_signed` mode that does not stop active interception, because the scraper cannot verify the certificate (see Residual risks). With `tls_mode: provided` the scraper pins the certificate, so an interceptor cannot pose as the exporter and never receives the password. With `tls_client_auth`, a client without a trusted certificate is refused at the TLS handshake, before any password check. No write endpoints. `MaxRequestsInFlight: 2` and a 9 s handler timeout bound concurrent scrape work. The process is non-root and confined, so a bug in the HTTP path lands in a process that can write only to `/tmp` and `/dev/null` and holds only a `default` token |
| **Malicious upstream strings**: app names, versions and repositories come from third-party app repositories; resolution reasons and backup metadata come from the Supervisor | Responses are decoded into structs holding only the fields exported; `options`, `ingress_entry` and `ingress_url` are never decoded. Every Supervisor call has a 5 s timeout and a 1 MiB body cap (a larger body is an error). Label values are sanitised to printable UTF-8 and truncated to 128 runes; app slugs must match the Supervisor's own slug pattern or are skipped and counted. At most 256 apps, 64 resolution `(type, context)` pairs per kind, and 64 series each for feature flags, boot slots and unhealthy and unsupported reasons; the rest is dropped and counted. Free text such as backup names, UUIDs and descriptions never becomes a label |
| **Compromised dependency**: a Go module, base image, GitHub Action or build tool | Few dependencies (the Prometheus client libraries); `go.sum` plus the Go checksum database; `GOTOOLCHAIN=local`. Base images pinned by digest, actions pinned by commit SHA, the gitleaks binary pinned by sha256; Dependabot for all three ecosystems. govulncheck, grype (fails on high or critical) and an SPDX SBOM in CI. CI uses no secrets, a read-only token and no `pull_request_target`. At runtime a compromised dependency is still boxed in by the `default` role, non-root, and the AppArmor profile: no writes outside `/tmp` and `/dev/null`, no exec, no capabilities, and `/proc/self/environ` unreadable. That last one stops a file-read bug from leaking the token. It does not stop dependency code inside the process, which can read the environment, the token, the hash and the authentication cache directly |

### Residual risks

- **In `self_signed` mode, TLS does not authenticate the server.** Use
  `tls_mode: provided` to close this; the rest of this item applies only
  without it. The certificate
  changes at every start and the scraper skips verification. An attacker
  who can intercept traffic on the LAN can impersonate the exporter and
  collect the password. Use a random password that is used nowhere else. If
  active interception is a risk on your network, keep the scrape path on a
  network segment that untrusted hosts cannot join, or scrape through a
  tunnel or proxy that verifies its peer. Limiting who can reach port 9100
  does not help here: an interceptor answers in the exporter's place.
- **Failed logins are not rate limited, and a flood of them can make scrapes
  time out.** Each login the toolkit has not cached costs one bcrypt
  comparison (tens of milliseconds at cost 10). The toolkit runs these one at
  a time and caches only 100 results, evicting at random. So any host that
  can reach port 9100 can, without credentials, keep one CPU core busy. With
  a few hundred concurrent clients sending distinct wrong passwords, it can
  evict the scraper's cached login and queue it behind the flood past
  Prometheus's 10 s scrape timeout, so the target reads as down. A long
  random password still makes guessing hopeless. Restrict who can reach host
  port 9100 to the Prometheus host, with a firewall in the network or the
  hypervisor. The toolkit's `rate_limit` is not a fix: it is one bucket for
  all clients, checked before authentication, so a single slow client could
  turn every scrape into a 429 (see DESIGN.md).
  With `tls_client_auth`, a client without a trusted certificate never
  reaches bcrypt. A flood then costs one TLS 1.3 handshake per connection,
  hundreds of times cheaper than a bcrypt comparison, but it is not free.
- **Seccomp is forced unconfined** by the Supervisor. The full kernel syscall
  surface is reachable from the process; AppArmor does not filter syscalls.
- **Read-only rootfs and cap-drop are not expressible.** Both rest on the
  non-root user and the AppArmor profile. If the profile were not loaded (a
  host without AppArmor), the Supervisor falls back to `apparmor=unconfined`
  and only DAC remains; the `apparmor_enforced` self-check reports this.
- **The token reaches more than the exporter uses.** Role `default` can read
  `/network/info` (addresses), `/hardware/info` (drive models and serials)
  and per-app info. The exporter never requests those, but code running in
  the process could. AppArmor cannot restrict network destinations, so such
  code could also send data anywhere the host can reach.
- **The hash travels in backups and debug logs.** Anyone holding a Home
  Assistant backup, or a Supervisor log taken at debug level, has the bcrypt
  hash and can attack it offline; again, use a long random password.
- **Trust in pinned digests.** Pins stop silent changes but not a dependency
  that was already malicious when pinned. Base images are not
  signature-verified.
- **The Supervisor may change.** Findings are measured against Supervisor
  2026.09.2 and 2026.09.3. The v1 `/supervisor/info` app list is deprecated;
  the v2 API moves it behind `manager`. When a release drops it, the app
  metrics stop without an error. The exporter will not take `manager` to keep
  them; DESIGN.md has the plan and the alerts to set.

## Install as a local app

While the repository is private there is no published image; the Supervisor
builds the image on the device from `haos_exporter/Dockerfile`.

1. Copy the `haos_exporter/` folder into the local apps folder on the device
   (`/local_apps` in the Terminal & SSH and Samba apps).
2. In the app store, reload (⋮ → **Check for updates**). **HAOS Exporter**
   appears under local apps. Install it.
3. Generate a bcrypt hash of a long random password (see
   [DOCS.md](haos_exporter/DOCS.md#generating-the-password-hash)) and set it
   as `basic_auth_password_hash`.
4. Start the app and add the scrape config from DOCS.md to Prometheus.
5. Check `haos_exporter_security_check`: every check should be `1`.

After changing `apparmor.txt`, bump `version` in `config.yaml` and update the
app: the Supervisor reloads the profile only on install or update, never on
rebuild.

## Development

The Go module is `haos_exporter/` (the app folder is the complete build
context). No local Go install is needed; every gate runs in the pinned Go
image. From the repository root:

```sh
GO_IMAGE=golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195
run_go() {
  docker run --rm -v "$PWD/haos_exporter:/src" -v haos-exporter-gomod:/go/pkg/mod \
    -w /src "$GO_IMAGE" sh -c "$1"
}

# gofmt
run_go 'test -z "$(gofmt -l .)" || { gofmt -l .; exit 1; }'
# vet and race tests
run_go 'go vet ./... && go test -race -count=1 ./...'
# govulncheck
run_go 'go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...'

# Image, built the way the Supervisor builds a local app
docker buildx build --platform linux/amd64 \
  --build-arg BUILD_ARCH=amd64 --build-arg BUILD_VERSION=0.1.0 \
  --load -t haos-exporter:dev haos_exporter
# Smoke test: read-only root filesystem, non-root user
docker run --rm --read-only --user 65532:65532 haos-exporter:dev --help

# Manifest and AppArmor assertions (needs PyYAML)
python3 ci/check_manifest.py haos_exporter

# Secrets, working tree and full history
gitleaks detect --source . --no-git --redact -v
gitleaks git --log-opts="--all" --redact -v .
```

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs the same
checks, plus grype, an SPDX SBOM, and an arm64 build with BuildKit provenance
and SBOM attestations.

A scan for deployment-specific strings (addresses, host and domain names) is
run before every publish with a pattern list that is kept outside the
repository on purpose: committing it would publish the very strings it looks
for.

## License

[Apache-2.0](LICENSE).
