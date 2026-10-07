# Verified TLS for the metrics endpoint: design

- **Date:** 2026-10-03
- **Status:** approved design, awaiting spec review
- **Version:** 0.4.0

## Problem

In the default `tls_mode: self_signed` the exporter makes a new certificate at every start, so the scraper has nothing stable to verify and has to skip verification. An attacker who can intercept traffic between the scraper and the exporter can pose as the exporter and collect the basic-auth password. The 2026-10-03 independent review rated this should-fix (finding 1).

A second, related problem: any host that can reach the port can make the exporter run a bcrypt comparison per request, because basic auth is the first check that runs.

## Goals

1. The scraper can verify the exporter's identity, against a pinned certificate.
2. The exporter can require a client certificate, so a client without one never reaches basic auth.
3. Each private key is generated where it is used. The server key never leaves the Home Assistant OS host, and never appears in backups, app options or logs.
4. No new runtime privilege beyond a read-only mount of the app's own config folder. Non-root, AppArmor in enforce mode and role `default` all stay as they are.
5. Both certificates can be rotated without restarting the exporter. Only a handshake that lands between the two moves of the server swap can fail; nothing bounds the number of such handshakes.

## Non-goals

- A certificate authority, ACME or automatic issuance.
- Automatic rotation.
- Removing basic auth. It stays mandatory in every mode, as a second layer.
- Changing the default mode. `self_signed` stays the default, so a fresh install works with no setup.

## Constraints

These were measured or read from source on 2026-10-03.

- **The exporter cannot keep a key itself.**
  - The Supervisor creates the app's `/data` as root (`supervisor/apps/app.py:940`, 2026.09.3).
  - The exporter runs as uid 65532.
  - The profile allows only `/data/ r`.
- **The `app_config` map provides a per-app folder:**
  - mounted at `/config`, and read-only by default (`apps/validate.py:500`);
  - created at every app start if it is missing (`apps/app.py:1316-1324`), so an update creates it too;
  - kept on uninstall, since `unload` removes only `/data`;
  - backed up with the `backup_exclude` filter applied (`apps/app.py:1550-1559`);
  - with no effect on the security rating (`apps/utils.py`, `rating_security`).
- **exporter-toolkit v0.20.0 re-reads the TLS configuration on every new connection**, including the certificate, the key and the client CA file (`web/tls_config.go:450-459`). Replacing a file therefore takes effect without a restart.
- **Go's `crypto/tls` accepts a pinned self-signed leaf as a trust anchor** and checks `server_name` against its SAN.
  - A self-signed client leaf in the server's client-CA pool works for mutual TLS.
  - A spike on 2026-10-03 confirmed four cases:
    - the right pin with a client certificate succeeds;
    - a wrong pin fails;
    - a wrong `server_name` fails;
    - a missing client certificate fails.
  - With TLS 1.3, that last refusal surfaces on the client's first read, not in the handshake.
- **The Terminal & SSH app:**
  - It runs as root, with no user-namespace remapping, so a `chown` to 65532 applies to the host's uid 65532.
  - Every app's config folder is visible at `/app_configs/<slug>`.
  - It has no `openssl`. `apk add openssl` installs 3.5.9 and also upgrades `libcrypto3`/`libssl3`. The install is lost when the app restarts.

## Design

### Manifest (`config.yaml`)

```yaml
version: "0.4.0"
map:
  - type: app_config
    read_only: true
backup_exclude:
  - "*.key"
options:
  # ...existing options...
  tls_mode: self_signed
  tls_client_auth: false
schema:
  # ...existing schema...
  tls_mode: "list(self_signed|provided|off)"
  tls_client_auth: bool
```

`backup_exclude` patterns are matched with `PurePath.match` against the full path, so `*.key` matches any `.key` file in the data or config folder. The live check below verifies this.

### Files in `/config`

| File | Content | Owner and mode | Needed when |
|---|---|---|---|
| `server.crt` | One PEM certificate | any; readable by uid 65532 | `tls_mode: provided` |
| `server.key` | The PEM private key matching `server.crt` | uid 65532, with no group or other bits (`0400` recommended) | `tls_mode: provided` |
| `client-ca.crt` | One or more PEM certificates trusted for client authentication | any; readable by uid 65532 | `tls_client_auth: true` |

### AppArmor (`apparmor.txt`)

Three read rules and nothing else under `/config`:

```
  /config/server.crt r,
  owner /config/server.key r,
  /config/client-ca.crt r,
```

`owner` means the profile itself refuses a key that uid 65532 does not own. Directory listing is not needed, because the toolkit opens files by path. The manifest `version` is bumped because the profile changes.

### Options and modes

| `tls_mode` | Server certificate | `tls_client_auth: true` |
|---|---|---|
| `self_signed` (default) | in memory, new at every start (unchanged) | allowed. It keeps clients without a certificate away from bcrypt, but does **not** protect the password from an interceptor, because the scraper cannot verify the server |
| `provided` | `/config/server.crt` + `/config/server.key` | allowed; the intended configuration |
| `off` | none | refused at start |

TLS 1.3 is the minimum version in every TLS mode.

### Startup validation (fail closed: log the reason and exit 1)

With `tls_mode: provided`, the exporter refuses to start when:

- `server.crt` or `server.key` is missing or unreadable. That includes an AppArmor denial, for example a key not owned by uid 65532.
- The mode of `server.key` has any group or other bit set.
- The key does not match the certificate (`tls.X509KeyPair` fails).
- The certificate is not currently valid: `NotBefore` is in the future or `NotAfter` is in the past.
- The certificate has no `serverAuth` extended key usage.
- The certificate has no subject alternative name. Go clients ignore the CN.

With `tls_client_auth: true`, it refuses to start when:

- `tls_mode` is `off`;
- `client-ca.crt` is missing or unreadable, or holds no parseable certificate.

These checks run only at start. After start, the scrape-time `tls` collector re-reads the files and reports failures as `haos_exporter_collector_success{collector="tls"} 0`. It never stops the exporter.

### Web configuration

In `provided` mode the generated web config references the files by path. The key is never copied into `/tmp`:

```yaml
tls_server_config:
  cert_file: /config/server.crt
  key_file: /config/server.key
  min_version: TLS13
  # only with tls_client_auth: true
  client_auth_type: RequireAndVerifyClientCert
  client_ca_file: /config/client-ca.crt
basic_auth_users:
  <user>: <bcrypt hash>
```

`self_signed` is unchanged, apart from `min_version: TLS13` and the optional client-auth lines. `off` is unchanged.

### Metrics

- `haos_exporter_tls_info{mode, client_auth} 1`.
- `haos_exporter_tls_certificate_expiry_timestamp_seconds{cert}`, read at scrape time:
  - `cert="server"`: `NotAfter` of `server.crt`, in `provided` mode only;
  - `cert="client_ca"`: the **latest** `NotAfter` in `client-ca.crt`, when client auth is on. A bundle holding an old and a new certificate during rotation then reports the new one.
- `collector="tls"` in the existing `haos_exporter_collector_success` and duration series.

### CI (`ci/check_manifest.py`)

- `map` and `backup_exclude` join `ALLOWED_KEYS`, and `map` leaves `FORBIDDEN_KEYS`.
- `map` must equal exactly `[{type: app_config, read_only: true}]`.
- `backup_exclude` must contain `*.key`.
- `options.tls_client_auth` must default to `false`.
- `apparmor.txt` must hold the `owner /config/server.key r` rule and no write rule under `/config`.
- New negative cases, each of which must fail:
  - `read_only: false`;
  - a second map entry;
  - `backup_exclude` missing;
  - a `/config` write rule.

### Key generation (operator procedure, documented in DOCS.md)

All of this runs in the Terminal & SSH app. `<slug>` is `local_haos_exporter` for a local install.

```sh
apk add openssl
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
apk del openssl
```

- **The client key** is generated on the scraper's side, with EKU `clientAuth` and 365 days' validity, and never touches the Home Assistant host. Only its certificate is copied into `client-ca.crt`.
- **Staging names matter for backups.** The Supervisor matches `backup_exclude` against the full path with `PurePath.match` (`apps/app.py`), and `server.key.new` does not match `*.key` while `server.new.key` does. The pair is therefore staged as `server.new.key` / `server.new.crt`, so a staged key is never captured by a scheduled backup. A `*.new` suffix would leave it unprotected until the scraper loads the new certificate, which can be days.
- **The scraper pins `server.crt`.** It is public, and is copied off the host with `cat`.
- **Between the two `mv` commands the files mismatch.** The toolkit reads the certificate and the key separately, so every handshake in that window fails. Normally the window is very short, but nothing bounds how many scrapes it catches; scrapes succeed again once a matching pair is in place. If the second `mv` never runs, every scrape fails until someone finishes the move or restores the previous pair.

### Scraper configuration (Prometheus)

```yaml
scheme: https
tls_config:
  ca_file: <copy of server.crt, or old+new during rotation>
  server_name: haos-exporter
  cert_file: <client certificate>
  key_file: <client key>
  min_version: TLS13
basic_auth: { ... unchanged ... }
```

There is no `insecure_skip_verify`.

### Rotation (no restart)

- **Server certificate:**
  1. Generate a new pair as `server.new.crt` / `server.new.key` on the host.
  2. Set the scraper's `ca_file` to old + new, and wait until the scraper has loaded it.
  3. `mv` the new files over the old ones. Handshakes during the swap can fail (see Key generation).
  4. Set `ca_file` to the new certificate only.
- **Client certificate:**
  1. Generate a new pair on the scraper's side.
  2. Set `client-ca.crt` to old + new on the host.
  3. Switch the scraper to the new client certificate.
  4. Set `client-ca.crt` to the new certificate only.

### Restore behaviour (accepted trade-off)

The key is left out of HA backups on purpose. After a restore, `server.crt` and `client-ca.crt` come back, but `server.key` does not. `provided` mode then refuses to start until the operator generates a new server pair and the scraper pins the new certificate. Monitoring sees the exporter down during that time.

### Reinstall under a new slug

Installing from a repository instead of the local folder changes the slug, and with it the config folder. The keys are placed again in the new folder, and the old folder, which survives uninstall, is deleted along with its key.

### Threat-model changes (README)

- **With `provided` + client auth:**
  - An interceptor cannot pose as the exporter, because the scraper pins it, so it never receives the password.
  - A client without a certificate is refused at the TLS handshake and never reaches bcrypt.
  - Handshake floods remain possible. Each costs the server a TLS 1.3 handshake, hundreds of times cheaper than a bcrypt comparison at cost 10.
- **`self_signed` keeps its existing residual risk.**
- **New asset: `server.key` in `/config`.**
  - Readable by root on the host and by apps that map every app's config folder, such as Terminal & SSH, Studio Code Server and Samba.
  - Not in backups, options or logs.
- **Permission table:**
  - new rows for `map: app_config` (read-only) and `backup_exclude`;
  - the "not requested" `map` row covers the other map types.

## Testing

- **Unit tests:**
  - option validation, covering every mode and client-auth combination, including `off` with client auth refused;
  - each startup refusal above;
  - web-config rendering, covering paths, `min_version` and the client-auth lines;
  - the `tls` collector: server expiry, the latest expiry in a bundle, and success 0 on a bad file.
- **Integration (Go, real listener).** Start the exporter in `provided` mode with client auth against temporary files, then check:
  - the right pin, `server_name`, client certificate and password get 200;
  - each of these is refused: no client certificate, a wrong pinned certificate, a wrong `server_name`, plain HTTP, and a client certificate outside `client-ca.crt`;
  - replacing `client-ca.crt` while it runs accepts the new client certificate;
  - replacing the server pair while it runs serves the new certificate.

  AppArmor cannot be exercised locally.
- **Live, on the Home Assistant host:**
  - the same accept and refuse cases, from another machine on the network;
  - a key owned by root is refused at start;
  - a backup of just this app contains `server.crt` and not `server.key`;
  - every `haos_exporter_security_check` reads 1;
  - the only AppArmor denial is the self-check's expected one.

## Rollout

These steps apply to an existing install. Each is verified by the scrape target being up, and each fits inside the scrape-down alert window.

1. **Update to 0.4.0 in `self_signed`.** The config folder is created at start. Place `server.crt`, `server.key` and `client-ca.crt`. Switch to `tls_mode: provided` with client auth off. The scraper still skips verification.
2. **The scraper pins `server.crt`** and presents its client certificate. The exporter does not require it yet.
3. **Switch on `tls_client_auth: true`.**
