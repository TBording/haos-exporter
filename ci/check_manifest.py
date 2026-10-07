#!/usr/bin/env python3
"""Assert the security-relevant parts of the app manifest and AppArmor profile.

The Supervisor drops unknown manifest keys without an error, so a typo in a
privilege key is invisible at install time. This check pins the values that
the README's permission table promises, and fails on any top-level key that
is not in ALLOWED_KEYS, so a new privilege key or a misspelling cannot slip in
unreviewed. It also pins the read-only app_config map, the *.key backup
exclusion and the three /config AppArmor rules.

Usage: python3 ci/check_manifest.py [app_dir]   (default: haos_exporter)
"""

import re
import sys
from pathlib import Path

import yaml

# Keys that grant a privilege or widen access. None of them may be present.
FORBIDDEN_KEYS = (
    "host_network",
    "host_pid",
    "host_ipc",
    "host_uts",
    "host_dbus",
    "docker_api",
    "full_access",
    "privileged",
    "homeassistant_api",
    "auth_api",
    "devices",
    "uart",
    "usb",
    "gpio",
    "video",
    "audio",
    "udev",
    "devicetree",
    "kernel_modules",
    "realtime",
    "journald",
    "ingress",
    "image",
)

# Every top-level key the manifest may hold. Adding one is a reviewed change.
ALLOWED_KEYS = frozenset((
    "name",
    "version",
    "slug",
    "description",
    "url",
    "arch",
    "stage",
    "startup",
    "boot",
    "init",
    "hassio_api",
    "hassio_role",
    "apparmor",
    "tmpfs",
    "map",
    "backup_exclude",
    "ports",
    "ports_description",
    "watchdog",
    "options",
    "schema",
))

# Same pattern as supervisor/utils/apparmor.py (RE_PROFILE).
RE_PROFILE = re.compile(r"^profile ([^ ]+).*$")


# The only rules the profile may have under /config (tls_mode: provided).
CONFIG_RULES = frozenset((
    "/config/server.crt r,",
    "owner /config/server.key r,",
    "/config/client-ca.crt r,",
))


def check(app_dir: Path) -> list[str]:
    """Return the manifest and profile errors in app_dir; empty means OK."""
    config = yaml.safe_load((app_dir / "config.yaml").read_text())
    errors = []

    def expect(key, want):
        got = config.get(key, "<missing>")
        if got != want:
            errors.append(f"config.yaml: {key} is {got!r}, want {want!r}")

    expect("hassio_api", True)
    expect("hassio_role", "default")
    expect("apparmor", True)
    expect("init", False)
    expect("tmpfs", True)

    for key in FORBIDDEN_KEYS:
        if key in config:
            errors.append(f"config.yaml: {key!r} must not be set (got {config[key]!r})")
    for key in sorted(set(config) - ALLOWED_KEYS - set(FORBIDDEN_KEYS)):
        errors.append(f"config.yaml: {key!r} is not in ALLOWED_KEYS (misspelled, or a new key to review)")

    if config.get("map") != [{"type": "app_config", "read_only": True}]:
        errors.append("config.yaml: map must be exactly [{type: app_config, read_only: true}]")
    if "*.key" not in (config.get("backup_exclude") or []):
        errors.append('config.yaml: backup_exclude must contain "*.key", so the server key stays out of backups')

    options = config.get("options", {})
    if options.get("basic_auth_password_hash", "<missing>") is not None:
        errors.append(
            "config.yaml: options.basic_auth_password_hash must default to null "
            "so the Supervisor refuses to start while it is unset"
        )
    if options.get("tls_mode") != "self_signed":
        errors.append("config.yaml: options.tls_mode must default to self_signed")
    if options.get("tls_client_auth") is not False:
        errors.append("config.yaml: options.tls_client_auth must default to false")

    profile = (app_dir / "apparmor.txt").read_text()
    names = [
        m.group(1)
        for m in (RE_PROFILE.match(line) for line in profile.splitlines())
        if m
    ]
    if len(names) != 1:
        errors.append(f"apparmor.txt: want exactly one ^profile line, found {len(names)}: {names}")
    if re.search(r"^\s*capability\b", profile, re.MULTILINE):
        errors.append("apparmor.txt: capability rules are not allowed")
    config_rules = {
        line.split("#", 1)[0].strip()
        for line in profile.splitlines()
        if "/config" in line.split("#", 1)[0]
    }
    if config_rules != CONFIG_RULES:
        errors.append(f"apparmor.txt: /config rules must be exactly {sorted(CONFIG_RULES)}, found {sorted(config_rules)}")
    return errors


def main() -> int:
    app_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "haos_exporter")
    errors = check(app_dir)
    for err in errors:
        print(f"FAIL {err}")
    if errors:
        return 1
    print(f"OK {app_dir}/config.yaml and apparmor.txt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
