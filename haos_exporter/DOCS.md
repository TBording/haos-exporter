# HAOS Exporter

A Prometheus exporter for Home Assistant OS. It reports on the machine and
the Supervisor, not on Home Assistant entities; for entity states use the
built-in [`prometheus:` integration](https://www.home-assistant.io/integrations/prometheus/).

**Tested on** Home Assistant OS 18.3 (`ova` board, an x86_64 VM) with
Supervisor 2026.09.2 and 2026.09.3 and Core 2026.9. The `aarch64` image
builds in CI but has not been run on arm64 hardware. This is an experimental
release.

## What it exports

Host series are read on every scrape. The Supervisor series are read with
`GET` requests in the background, every 60 s or 5 min depending on the
endpoint, and a scrape serves the latest result; see
[Supervisor log volume](#supervisor-log-volume). Full metric list, labels and
sources: [DESIGN.md](https://github.com/TBording/haos-exporter/blob/main/DESIGN.md#metrics).

- **Host** (node_exporter names, so existing dashboards and rules work):
  `node_cpu_seconds_total`, `node_load1/5/15`, `node_memory_*_bytes`,
  `node_boot_time_seconds`, `node_time_seconds`, `node_uname_info`.
- **Disk IO** per disk and per partition: `node_disk_*` from
  `/proc/diskstats` (`zram`, `loop` and device-mapper devices are left out).
- **Pressure stall information**: `node_pressure_*` from `/proc/pressure/*`,
  where the kernel provides it.
- **Data partition**: `node_filesystem_{size,free,avail}_bytes` for
  `mountpoint="/mnt/data"`, from `statfs` on the app's own `/data`, which
  sits on the same filesystem. These match `ha host info` at byte precision.
  Alert on `avail`: the Supervisor refuses updates, backups and app installs
  when it drops below 2 GiB.
- **Supervisor**: `haos_supervisor_healthy`, `haos_supervisor_supported`,
  `haos_supervisor_feature_flag`, and the resolution center
  (`haos_resolution_unhealthy`, `haos_resolution_unsupported`,
  `haos_resolution_issues`, `haos_resolution_suggestions`).
- **Versions and updates**: `haos_component_version_info`,
  `haos_component_update_available` (Core, Supervisor, OS),
  `haos_updates_pending`, `haos_os_boot_slot_info`.
- **Apps**: `haos_app_info`, `haos_app_state`, `haos_app_update_available`,
  and `haos_supervisor_app_list_present`. It is 0 when the Supervisor's
  `/supervisor/info` no longer carries its app list; the app series and the
  app update count are then left out, and the app log shows an ERROR.
- **Core liveness**: `haos_core_up`, from an unauthenticated
  `GET /manifest.json` against Core. 1 means Core answered HTTP with any
  status, an error such as 500 included; 0 means no answer (connection error
  or timeout). It shows that Core's web server is up, not that Home Assistant
  is working correctly. The exporter never calls Core's `/api/`: every 401
  there counts as a failed login and raises a notification.
- **Backups**: `haos_backups`, `haos_backups_size_bytes`,
  `haos_backup_latest_timestamp_seconds` per type.
- **Disk wear**: `haos_host_disk_life_time_used_ratio`, where the hardware
  reports it.
- **The exporter itself**: `haos_exporter_collector_success`,
  `haos_exporter_collector_duration_seconds`,
  `haos_exporter_series_dropped_total`, `haos_exporter_security_check`,
  `haos_exporter_build_info`, plus the standard `go_*` and `process_*`. It also
  reports `haos_exporter_tls_info{mode,client_auth}`, and, with
  `tls_mode: provided` or `tls_client_auth`,
  `haos_exporter_tls_certificate_expiry_timestamp_seconds{cert}`.

### Not exported, by design

- **Per-container CPU and memory** for Core, the Supervisor and apps. Their
  Supervisor stats endpoints need the `manager` role (Core's also
  `homeassistant`), and `manager` can also add a store repository and install
  an app from it. A network-facing process should not hold that token.
- **Host network interface counters.** Without `host_network` the app only
  sees its own container interface. If Home Assistant OS runs in a VM, the
  hypervisor already exports the VM's NIC counters.
- **Boot partition usage.** `/mnt/boot` is not visible inside an app
  container.

## Configuration

| Option | Default | Meaning |
|---|---|---|
| `basic_auth_username` | `prometheus` | Username for basic auth. |
| `basic_auth_password_hash` | none, **required** | bcrypt hash of the scrape password. The app does not start until it is set. |
| `tls_mode` | `self_signed` | `self_signed` serves HTTPS with a certificate generated in memory at every start. `provided` serves `server.crt` and `server.key` from this app's config folder (see Verified TLS). `off` serves plain HTTP. |
| `tls_client_auth` | `false` | Require a client certificate trusted by `client-ca.crt` in the config folder. Needs TLS. |
| `log_level` | `info` | `debug`, `info`, `warn` or `error`. |

If you edit the options as YAML, quote `"off"`. In YAML 1.1, a bare `off` is
the boolean `false`, and the Supervisor then rejects the value.

### Generating the password hash

Enter the **hash** in `basic_auth_password_hash`, never the password. Keep the
password itself out of your shell history and process list: use a tool that
prompts for it or reads it from standard input, not one that takes it as an
argument.

With `htpasswd` (Apache `httpd` tools; preinstalled on macOS):

```sh
htpasswd -nBC 10 "" | tr -d ':\n'; echo
```

It prompts twice without echo and prints only the hash. This is the command
the [exporter-toolkit documentation](https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md#about-bcrypt)
recommends. To feed the password from a file or a password manager instead,
`-i` reads it from standard input:

```sh
htpasswd -niBC 10 "" < haos-exporter-password | tr -d ':\n'; echo
```

Or with Python's `bcrypt` package:

```sh
python3 -c 'import bcrypt, getpass; print(bcrypt.hashpw(getpass.getpass().encode(), bcrypt.gensalt(10)).decode())'
```

About the cost factor (`10` above), from the exporter-toolkit documentation:
a higher cost slows every new authentication; cost 10 takes about 70 ms, cost
18 can take seconds. The hash is computed on the first authenticated request
and then cached. Cost 10 is the recommended value.

Save the password in a file for Prometheus (next section) and the hash in the
app options.

### TLS

`self_signed` protects the password from passive capture on the network. It
does **not** prove to Prometheus that it is talking to this exporter: the
certificate is new at every start, so there is nothing stable to verify, and
with `self_signed` the scrape config has to skip verification (see
the comment in the scrape config below). An attacker who can intercept
traffic on your network could impersonate the exporter and collect the
password; use a password that is not used anywhere else. If that is a risk on
your network, keep the scrape path on a network segment that untrusted hosts
cannot join, or scrape through a tunnel or proxy that verifies its peer.

`off` sends the password in clear text with every scrape. Use it only if the
network path is otherwise protected.

### Verified TLS (`provided`) and client certificates

With `tls_mode: provided`, Prometheus pins this app's certificate, so nothing
else can pose as the exporter. With `tls_client_auth: true`, the exporter
serves only a client that presents a certificate you issued. Use both.

The files live in this app's config folder. It is mounted read-only at
`/config` inside the app, and in the Terminal & SSH app it is
`/app_configs/<slug>`, where `<slug>` is the app's slug as `ha apps list`
shows it. An app installed from a repository gets a prefix derived from the
repository URL; a local install is `local_haos_exporter`. Each private key is generated
where it is used: the server key on Home Assistant OS, and the client key
wherever Prometheus runs.

**1. The server pair**, in the Terminal & SSH app:

```sh
apk add openssl           # not installed by default; gone after the app restarts
D=/app_configs/<slug>
umask 077
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -pkeyopt ec_param_enc:named_curve -nodes -days 365 \
  -subj /CN=haos-exporter -addext subjectAltName=DNS:haos-exporter \
  -addext extendedKeyUsage=serverAuth -addext keyUsage=digitalSignature \
  -keyout "$D/server.new.key" -out "$D/server.new.crt"
chown 65532:65532 "$D/server.new.key" && chmod 0400 "$D/server.new.key"
chmod 0444 "$D/server.new.crt"
mv "$D/server.new.crt" "$D/server.crt" && mv "$D/server.new.key" "$D/server.key"
cat "$D/server.crt"       # public: copy it to Prometheus as its CA file
apk del openssl
```

The exporter refuses a key that it does not own, or that group or others can
read. The key is staged as `server.new.key` on purpose: the backup exclusion
matches `*.key`, so a staged key is left out of backups too.

**2. The client pair**, on the machine that holds Prometheus's secrets:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -pkeyopt ec_param_enc:named_curve -nodes -days 365 \
  -subj /CN=prometheus -addext extendedKeyUsage=clientAuth \
  -addext keyUsage=digitalSignature -keyout client.key -out client.crt
```

Copy only `client.crt` (public) to `/app_configs/<slug>/client-ca.crt`, mode
0444. `client.key` stays with Prometheus.

Keep `-pkeyopt ec_param_enc:named_curve` in these commands. Without it,
macOS's built-in `openssl` (LibreSSL) writes the key with explicit curve
parameters. Go rejects those (`x509: invalid ECDSA parameters`), so
Prometheus and the exporter cannot use the key. OpenSSL uses the named curve
by default; the option makes both behave the same.

**3. Switch the options, in this order**, restarting the app after each
change. The app refuses to start if a file is missing or wrong, and its log
says which.

1. Set `tls_mode: provided`.
2. In Prometheus's `tls_config` (see the scrape config below), set `ca_file`
   and `server_name`, add `cert_file` and `key_file`, and **delete
   `insecure_skip_verify`**. If you followed an older version of these docs
   you set it to `true`; while it is present Prometheus accepts any
   certificate and `ca_file` pins nothing. Confirm the target is up.
3. Set `tls_client_auth: true`, once Prometheus is configured with
   `cert_file` and `key_file`.

**Rotation** needs no restart: the exporter re-reads the files on every
connection. Rotate the server certificate like this, in the Terminal & SSH
app:

```sh
D=/app_configs/<slug>
umask 077
# 1. Generate the new pair (install openssl first, as above).
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -pkeyopt ec_param_enc:named_curve -nodes -days 365 \
  -subj /CN=haos-exporter -addext subjectAltName=DNS:haos-exporter \
  -addext extendedKeyUsage=serverAuth -addext keyUsage=digitalSignature \
  -keyout "$D/server.new.key" -out "$D/server.new.crt"
chown 65532:65532 "$D/server.new.key" && chmod 0400 "$D/server.new.key"
chmod 0444 "$D/server.new.crt"
cat "$D/server.new.crt"
# 2. STOP here. Give Prometheus a CA file holding the old and the new
#    certificate, and wait until it has loaded it. Moving the files before
#    that breaks the pin.
# 3. Then move the new pair into place.
mv "$D/server.new.crt" "$D/server.crt" && mv "$D/server.new.key" "$D/server.key"
# 4. Finally, drop the old certificate from Prometheus's CA file.
```

Do not leave `server.new.key` lying around: it is the next key, and only the
`*.key` name keeps it out of backups.

Between the two `mv` commands the certificate and the key do not match, and
the exporter reads them separately on every connection. Any handshake in
that window fails, so scrapes can fail; how many depends on how long the
window lasts, and nothing bounds it. Scrapes succeed again once a matching
pair is in place. If the second `mv` does not run, every scrape fails until
it does: finish it, or restore the previous pair. A client rotation works the same way:
`client-ca.crt` holds both certificates while Prometheus switches.

`haos_exporter_tls_certificate_expiry_timestamp_seconds{cert}` reports the
server certificate's expiry (`cert="server"`) and, with `tls_client_auth`, the
client CA's (`cert="client_ca"`). Alert well before them.

**After a Home Assistant restore**, `server.key` is missing on purpose: it is
excluded from backups. The app refuses to start until you repeat step 1 and
give Prometheus the new certificate.

## Supervisor log volume

The Supervisor logs every API request an app makes at INFO, as
`<path> access from <app>`. The exporter polls six endpoints on its own
schedule, independent of how often Prometheus scrapes, which comes to about
4,000 lines a day:

- `/supervisor/info` and `/resolution/info` every 60 s;
- `/host/info`, `/os/info`, `/core/info` and `/backups/info` every 5 min.

`haos_exporter_collector_last_success_timestamp_seconds{collector}` and
`haos_exporter_collector_poll_interval_seconds{collector}` let you alert on a
poll that has stopped succeeding.

## Prometheus scrape config

```yaml
scrape_configs:
  - job_name: haos
    # Any interval works: scrapes make no Supervisor calls (see below).
    scrape_interval: 15s
    # The exporter's handler times out at 9 s, inside this 10 s.
    scrape_timeout: 10s
    scheme: https
    tls_config:
      # tls_mode: provided. Pin the app's server.crt; its SAN is haos-exporter.
      ca_file: /etc/prometheus/secrets/haos-exporter/server.crt
      server_name: haos-exporter
      min_version: TLS13
      # tls_client_auth: true
      cert_file: /etc/prometheus/secrets/haos-exporter/client.crt
      key_file: /etc/prometheus/secrets/haos-exporter/client.key
      # With tls_mode: self_signed instead, there is nothing to verify: drop
      # ca_file and server_name and set insecure_skip_verify: true (see TLS).
      # Keep cert_file and key_file if tls_client_auth is on. Never combine
      # insecure_skip_verify with ca_file: it overrides the pin.
    basic_auth:
      username: prometheus
      # A file holding only the password (not the hash), readable by Prometheus.
      password_file: /etc/prometheus/secrets/haos-exporter/password
    static_configs:
      - targets: ["homeassistant.local:9100"]
```

Useful first alerts: `haos_exporter_collector_success == 0`,
`haos_supervisor_healthy == 0`, `haos_core_up == 0`, and
`node_filesystem_avail_bytes{mountpoint="/mnt/data"}` below a few GiB.

Two more watch for the Supervisor's deprecated app list going away (see
[DESIGN.md](https://github.com/TBording/haos-exporter/blob/main/DESIGN.md#why-role-default)):

- `haos_supervisor_feature_flag{flag="supervisor_v2_api"} == 1`: the v2
  API is on, an early sign of the migration.
- `haos_supervisor_app_list_present == 0`: the Supervisor no longer sends
  the app list, so the app metrics are gone.

## Network

The app publishes container port 9100 on host port 9100 on every host
interface. You can change or clear the host port under the app's
**Network** settings; clearing it stops the port being published.

## Security notes

- The app uses the Supervisor role `default`, which reaches `/<x>/info`
  paths plus the few routes every app token has, such as its own options.
  At start it runs some diagnostics: `haos_exporter_security_check` reports
  whether it runs as non-root with no capabilities, under an AppArmor
  profile in enforce mode, whether that profile blocks a write, and whether a
  `manager`-only Supervisor path is refused (1 = as intended). These are
  diagnostics, not proof: the AppArmor check accepts any profile in enforce
  mode, not this app's by name, and tests one denial, not the whole policy.
  A failed check is logged as a warning; the exporter keeps serving.
- Some log lines at each start are expected, because the self-check makes
  two requests that must fail:
  - one AppArmor `DENIED` line in the host log: the write attempt under
    `/dev/shm`, which proves the profile blocks it;
  - a Supervisor log warning `/addons no role for <app slug>`, followed by
    `Invalid token for access /addons`: the `manager`-only request. Its
    refusal shows the token is below `manager`; the `homeassistant` and
    `backup` roles would be refused too.
- The exporter keeps no state. It writes nothing outside the `/tmp` tmpfs,
  `/data` holds nothing but what the Supervisor puts there, and `/config`
  is mounted read-only.

## Support

Issues: <https://github.com/TBording/haos-exporter/issues>. Security reports:
see `SECURITY.md` in the repository; please do not file them as issues.
