# Public-flip checklist

Everything that must be done, in order, before this repository's visibility
changes from private to public, and the settings that only become available
once it is public. Tick each box in the pull request that performs it.

Section 1 was done in a private development repository. This repository was
created on 2026-10-07 from a history-free snapshot of it, and sections 2–5
are done here. Pull request numbers in section 1 refer to the development
repository.

Action SHAs below were resolved on 2026-09-28. Re-resolve each one from its
release tag at the time you add it; never type a SHA from memory.

## 1. Before the flip: content

- [x] **gitleaks over the full history**, not just the working tree:
      `gitleaks git --log-opts="--all" --redact -v .` on a fresh clone with
      every branch and tag fetched. Use `git clone --mirror`, which also
      fetches the read-only `refs/pull/*` heads that turn public with the
      repository. Zero findings, or each finding rewritten out of history.
- [x] **Deployment-specific strings scan**, run from **outside** the
      repository, with a pattern list kept **outside** the repository
      (private addresses and subnets, internal domain and host names, VM and
      machine identifiers, MAC and IPv6 prefixes, VPN/tailnet names, tokens).
      The list is not committed because committing it would publish exactly
      the strings it exists to keep out. Scan the working tree and every
      commit (`git log -p --all` on the mirror clone), and everything else
      that turns public with the repository: issue, pull request and review
      text, and Actions run logs and artifacts. First run the list over a
      file holding one example per pattern, to prove each pattern fires. The
      GitHub owner handle appears legitimately (repository URL, Go module
      path, `LICENSE`); allow it explicitly rather than weakening the
      pattern.
- [x] **Commit author emails.** Every commit's author and committer email
      becomes public. Rewriting `main` does not remove an address from the
      pull request heads: GitHub keeps `refs/pull/*` read-only, and its
      Support removes only sensitive data. The push-event payload in Actions
      run logs and build records repeats the addresses too. So either accept
      the addresses as they are, or publish a new repository from rewritten
      history and keep the old one private (issues can be transferred, pull
      requests cannot). Decide explicitly. Either way, set `user.email` to the
      `users.noreply.github.com` address before committing here, so new pull
      request heads add no address.
      **Decided 2026-10-04:** publish a new repository from a history-free
      snapshot of `main` (`git archive`), and keep the private development repository private.
      Sections 2–5 then apply to the new repository. Its first commit must
      use the noreply address.
- [x] **Test fixtures** under `haos_exporter/testdata` hold only generic,
      made-up values (hostnames, slugs, UUIDs, machine IDs, addresses in
      `172.30.32.0/23`).
- [x] `SECURITY.md` names GitHub private vulnerability reporting as the
      disclosure route and contains no email address.
- [x] `LICENSE` is present (Apache-2.0).
- [x] The README's threat model and permission table match `config.yaml`
      and `apparmor.txt` as they are now.
- [x] **Independent review** of the manifest permissions (`config.yaml`,
      `apparmor.txt`) and the auth defaults (mandatory basic auth,
      `tls_mode: self_signed`), by someone other than the author of the
      current version. Record the reviewer and date in the pull request.
      Done: the review on 2026-10-03 (PR 9) found 1 should-fix and 5 nits,
      all fixed (PRs 9–13). The confirmation pass on 2026-10-04
      (GitHub Copilot CLI 1.0.91, `gpt-6.1-sol`, over `ece97c0..b82a01d`)
      found **no open issue**. Copilot's content policy kept `.github/` out
      of that review, so the workflows and Dependabot configuration had their
      own review on 2026-10-04 (Gemini 3.1 Pro, Antigravity CLI): 1
      should-fix and 2 nits, all addressed in PR 16, and its re-check found
      **no open issue**.
- [x] **Re-run both scans last**, after every other box in this section:
      review fixes and the pull requests that tick these boxes add commits.
      Done 2026-10-04, last on the tree of PR 16, after the assessment's doc
      fixes (PR 15) and the workflow review's fixes (PR 16):
      - gitleaks: no leaks, over every ref and the `git archive` snapshot
        (70 files);
      - the strings scan, with 23 pattern classes, each proven on a canary
        first: the snapshot holds nothing deployment-specific.

      The history, the issue and PR text, and the Actions logs still hold the
      owner's personal email and references to a private repository. That is
      why the private development repository stays private and only the snapshot is published.

## 2. The flip

- [x] Change the repository visibility to public.
      Done 2026-10-07. The repository was created private, and its first
      commit's tree is identical to the scanned snapshot. Before the flip,
      the strings scan and an email check covered every log and artifact of
      the first runs (CI on push, both Dependabot pull requests, Dependabot's
      own jobs) and the Dependabot pull request text: nothing
      deployment-specific and no personal address.

## 3. Immediately after: repository settings

These are unavailable on a free private repository and become available
when it is public.

- [x] **Secret scanning** enabled, and **push protection** enabled.
- [x] **Private vulnerability reporting** enabled in the repository's security settings.
      `SECURITY.md` already points to it.
- [x] Remove `SECURITY.md`'s private-phase paragraph ("Private
      vulnerability reporting can only be enabled once this repository is
      public ...") in the same change.
- [x] **Dependabot alerts** and **Dependabot security updates** still
      enabled (they work while private; check they survived the flip).
      Enabled on creation and read back after the flip.
- [x] **Actions settings**: default workflow token permissions set to
      read-only; "Allow GitHub Actions to create and approve pull requests"
      off; approval required before running workflows from fork pull
      requests by outside contributors. The token settings were set before
      the first push; fork approval (all outside contributors) can only be
      set on a public repository, so it was set right after the flip.
- [x] **Ruleset on `main`**:
  - [x] block force pushes;
  - [x] block deletion;
  - [x] require a pull request before merging (squash only);
  - [x] require status checks: the `ci.yml` jobs (Go, gitleaks, image,
        manifest), and CodeQL once added. Each check is pinned to the
        GitHub Actions app, so a status from anything else does not count;
  - [x] repository admin on the bypass list, in "pull requests only" mode:
        an admin can merge a pull request past a rule, but cannot push to
        `main` directly.
- [x] **Require signed commits**, but **only with repository admin on the
      bypass list**. GitHub checks every commit a pull request introduces,
      including unsigned commits on the head branch, so unsigned head commits
      block even a squash merge, although GitHub signs the squash commit
      itself. Without the bypass, every pull request authored without local
      commit signing is unmergeable. Dependabot's commits are signed by
      GitHub and pass.
      Done 2026-10-07 in the same ruleset as above, under the same bypass.

## 4. After the flip: CI and supply chain

- [x] **CodeQL** for Go: `github/codeql-action` v4.38.2
      (`2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2` as of 2026-09-28), with
      top-level `permissions: contents: read` and `security-events: write`
      on that job only. Done in `codeql.yml` (re-resolved 2026-10-07: still
      v4.38.2 at that SHA). It joins the ruleset's required checks once it
      has run on `main`.
- [x] **Dependency review** on pull requests (available for public
      repositories), SHA-pinned. Done in `dependency-review.yml`
      (`actions/dependency-review-action` v5.0.0), failing on high severity.
- [x] **harden-runner** (`step-security/harden-runner` v2.21.1,
      `e14015d583714f6e62063499dc959a02595150a1`) as the first step of each
      job, starting in audit mode. Its private-repository tier is
      Enterprise-only, so it was deferred until now. Done with v2.22.0
      (`351661ca32ac09a36dc5ee2d536e3128f2a3c8ed`, the current release on
      2026-10-07) in every job of every workflow.
- [x] **Release workflow** that, on a version tag, builds `linux/amd64` and
      `linux/arm64` and publishes to GHCR (`ghcr.io/tbording/haos-exporter`)
      with immutable, versioned tags only, never a rolling `latest`. It
      needs `packages: write` and `id-token: write` on that job only, and
      the pinned `docker/login-action` v4.6.0
      (`dbcb813823bdd20940b903addbd779551569679f`) and
      `docker/metadata-action` v6.2.0
      (`dc802804100637a589fabce1cb79ff13a1411302`).
      Done in `release.yml`. `docker/metadata-action` turned out unnecessary:
      the single version tag and the revision label are set directly, which
      keeps one third-party action out of the most privileged job. The tag
      must match `config.yaml`'s version and be on `main`; a published
      version is never replaced. `v0.4.0` published on 2026-10-07 (run
      37581640422): index `sha256:db45add3c4bc…`, amd64 `sha256:503c0d53672f…`,
      arm64 `sha256:fcce4e8e7a98…`, each with the right `io.hass.arch`.
  - [x] **cosign keyless signing**: `sigstore/cosign-installer` v4.1.2
        (`6f9f17788090df1f26f669e9d70d6ae9567deba6`) with
        `cosign-release: v3.1.3`; sign by digest.
  - [x] **SLSA provenance**: `actions/attest-build-provenance` v4.2.2
        (`4d101475d8b20a2381f78447822ac1eab6504dd8`).
  - [x] **SBOM attestation**: `actions/attest-sbom` v4.1.0
        (`c604332985a26aa8cf1bdc465b92731239ec6b9e`) over the SPDX SBOM.
        `attest-sbom` is deprecated and only wraps `actions/attest`, so
        `actions/attest` v4.2.2 is used directly, once per platform image.
  - [x] Verification documented and tried once: `cosign verify` with the
        workflow identity, and `gh attestation verify`.
        Documented in the README (Releases). Tried on 2026-10-07 against
        `0.4.0`: cosign verified the index and both images, and rejected a
        wrong workflow identity; `gh attestation verify` verified the SLSA
        provenance of the index and the SPDX 2.3 SBOM of each image, and
        rejected the wrong repository.
  - Why this waited for the flip: keyless signing writes a permanent entry
    to the public Rekor transparency log. The signing certificate records
    the repository name, workflow path, refs, commit SHAs, run IDs and the
    repository's visibility at signing time. Signing while private would
    have published the repository's existence and its "private" status,
    permanently. GitHub's own attestations are not available on a free
    private repository at all.
- [x] Make the **GHCR package public**. This is **irreversible**: a public
      package cannot be made private again.
      It became public by itself: a package first published by a public
      repository's workflow inherits the repository's visibility. So it was
      public from the first push, before the verification above rather than
      after it. The verification then passed, and an anonymous pull works.
- [x] Add `image: ghcr.io/tbording/haos-exporter` to `config.yaml`, with
      `version` matching a published tag, and move `image` from
      `FORBIDDEN_KEYS` to `ALLOWED_KEYS` in `ci/check_manifest.py`. Installing from the GitHub
      repository is a different app from the local one (its slug gets the
      repository's prefix instead of `local_`), so this is a **reinstall**:
      uninstall the local app, add the repository, install, and enter the
      options again. The AppArmor profile is loaded under the new slug.
      `check_manifest.py` now requires `image` to be exactly that name, with
      no tag and no `{arch}`. The reinstall is recorded with the next box.
- [x] **Place the TLS files again under the new slug.** The reinstall gives
      the app a new config folder, `/app_configs/<repo-prefix>_haos_exporter`.
      Generate a new server pair there (DOCS.md, Verified TLS), copy
      `client-ca.crt`, re-pin Prometheus, and delete the old
      `/app_configs/local_haos_exporter`, which survives uninstall and still
      holds the old key.
      Done 2026-10-07 as `bbee2835_haos_exporter`, with one deviation: the
      existing pair and `client-ca.crt` were copied (`cp -p`, owner and mode
      kept) into the new folder before the first start, instead of a new
      pair being generated. The key never left the device, so Prometheus's
      pin did not change. The options were copied through the Supervisor
      API, and the watchdog turned on. The switch from the stopped local app
      to the new one took about 2 s. After the scrape, all five security
      checks, the client-certificate refusal and the app list were verified,
      the local app was uninstalled with `--remove-config`, which deleted
      `/app_configs/local_haos_exporter` and its key, and its source in
      `/local_apps` was removed.
- [x] Re-run the whole CI on `main` after all of the above and confirm every
      required check passes.
      Done: `main` at the last repository change (the `image:` manifest)
      passed all five required checks (Go, gitleaks, image, manifest,
      CodeQL).

## 5. Sign-off

- [x] Every box above is ticked, and the independent review found no open
      issue. The reviews: the manifest and auth review and its confirmation
      pass (section 1), the review of `.github/` in the development
      repository, and the review of this repository's new workflows (#5);
      each ended with no open issue.

Sections 2–5 were carried out on 2026-10-07 by Claude Code under the
owner's authorization. The signature below is the owner's, written into
this file by Claude Code on the owner's instruction ("Sign the public-flip
checklist").

Signed off by: TBording (repository owner)  Date: 2026-10-07
