# HAOS Exporter

Prometheus metrics for Home Assistant OS itself: host CPU, memory, load and
data-disk space, Supervisor health and resolution-center state, pending OS,
Supervisor, Core and app updates, per-app state, and backup count, size and
age.

It runs as one unprivileged container. Protection mode stays on, it uses the
lowest Supervisor API role (`default`), a custom AppArmor profile in enforce
mode and a non-root user. The metrics endpoint requires basic auth and serves
HTTPS by default.

Home Assistant entity states are not exported; the built-in `prometheus:`
integration already does that.

See the Documentation tab for setup and the Prometheus scrape config.
