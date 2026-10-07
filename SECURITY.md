# Security policy

## Supported versions

Only the latest released version of the app receives fixes. There are no
backports to older versions.

| Version | Supported |
|---|---|
| latest 0.x release | yes |
| anything older | no |

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's private vulnerability
reporting: open the repository's **Security** tab and choose **Report a
vulnerability**. Do not open a public issue, pull request or discussion for a
suspected vulnerability.

Private vulnerability reporting can only be enabled once this repository is
public. Until then the repository is private, so only its collaborators can
read this file; raise a suspected vulnerability with the maintainer directly
on GitHub.

This is a personal project maintained on a best-effort basis. Reports are
acknowledged and fixed as time allows, and the fix is credited in the
changelog unless you ask otherwise.

## Scope

In scope:

- The exporter binary and its handling of Supervisor responses, credentials
  and metrics.
- The app manifest (`haos_exporter/config.yaml`): requested privileges and
  defaults.
- The AppArmor profile (`haos_exporter/apparmor.txt`).
- The container image and the CI workflows in this repository.

Out of scope: vulnerabilities in Home Assistant, the Supervisor, Home
Assistant OS or upstream dependencies themselves; please report those to
their projects. Issues that require a compromised Home Assistant
administrator account are also out of scope.

The threat model and the permission table are in the [README](README.md).
