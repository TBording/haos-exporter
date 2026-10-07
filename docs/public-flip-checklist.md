# Public-flip checklist

Everything that must be done, in order, before this repository's visibility
changes from private to public, and the settings that only become available
once it is public. Tick each box in the pull request that performs it.

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
      history and keep this one private (issues can be transferred, pull
      requests cannot). Decide explicitly. Either way, set `user.email` to the
      `users.noreply.github.com` address before committing here, so new pull
      request heads add no address.
      **Decided 2026-10-04:** publish a new repository from a history-free
      snapshot of `main` (`git archive`), and keep this repository private.
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
      Done: the review on 2026-10-03 (#9) found 1 should-fix and 5 nits, all
      fixed (#9, #10, #11, #12, #13). The confirmation pass on 2026-10-04
      (GitHub Copilot CLI 1.0.91, `gpt-6.1-sol`, over `ece97c0..b82a01d`)
      found **no open issue**. Copilot's content policy kept `.github/` out
      of that review, so the workflows and Dependabot configuration had their
      own review on 2026-10-04 (Gemini 3.1 Pro, Antigravity CLI): 1
      should-fix and 2 nits, all addressed in #16, and its re-check found
      **no open issue**.
- [x] **Re-run both scans last**, after every other box in this section:
      review fixes and the pull requests that tick these boxes add commits.
      Done 2026-10-04, last on the tree of #16, after the assessment's doc
      fixes (#15) and the workflow review's fixes (#16):
      - gitleaks: no leaks, over every ref and the `git archive` snapshot
        (70 files);
      - the strings scan, with 23 pattern classes, each proven on a canary
        first: the snapshot holds nothing deployment-specific.

      The history, the issue and PR text, and the Actions logs still hold the
      owner's personal email and references to a private repository. That is
      why this repository stays private and only the snapshot is published.

## 2. The flip

- [ ] Change the repository visibility to public.

## 3. Immediately after: repository settings

These are unavailable on a free private repository and become available
when it is public.

- [ ] **Secret scanning** enabled, and **push protection** enabled.
- [ ] **Private vulnerability reporting** enabled in the repository's security settings.
      `SECURITY.md` already points to it.
- [ ] Remove `SECURITY.md`'s private-phase paragraph ("Private
      vulnerability reporting can only be enabled once this repository is
      public ...") in the same change.
- [ ] **Dependabot alerts** and **Dependabot security updates** still
      enabled (they work while private; check they survived the flip).
- [ ] **Actions settings**: default workflow token permissions set to
      read-only; "Allow GitHub Actions to create and approve pull requests"
      off; approval required before running workflows from fork pull
      requests by outside contributors.
- [ ] **Ruleset on `main`**:
  - [ ] block force pushes;
  - [ ] block deletion;
  - [ ] require a pull request before merging;
  - [ ] require status checks: the `ci.yml` jobs (Go, gitleaks, image,
        manifest), and CodeQL once added;
  - [ ] repository admin on the bypass list.
- [ ] **Require signed commits**, but **only with repository admin on the
      bypass list**. GitHub checks every commit a pull request introduces,
      including unsigned commits on the head branch, so unsigned head commits
      block even a squash merge, although GitHub signs the squash commit
      itself. Without the bypass, every pull request authored without local
      commit signing is unmergeable. Dependabot's commits are signed by
      GitHub and pass.

## 4. After the flip: CI and supply chain

- [ ] **CodeQL** for Go: `github/codeql-action` v4.38.2
      (`2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2` as of 2026-09-28), with
      top-level `permissions: contents: read` and `security-events: write`
      on that job only.
- [ ] **Dependency review** on pull requests (available for public
      repositories), SHA-pinned.
- [ ] **harden-runner** (`step-security/harden-runner` v2.21.1,
      `e14015d583714f6e62063499dc959a02595150a1`) as the first step of each
      job, starting in audit mode. Its private-repository tier is
      Enterprise-only, so it was deferred until now.
- [ ] **Release workflow** that, on a version tag, builds `linux/amd64` and
      `linux/arm64` and publishes to GHCR (`ghcr.io/tbording/haos-exporter`)
      with immutable, versioned tags only, never a rolling `latest`. It
      needs `packages: write` and `id-token: write` on that job only, and
      the pinned `docker/login-action` v4.6.0
      (`dbcb813823bdd20940b903addbd779551569679f`) and
      `docker/metadata-action` v6.2.0
      (`dc802804100637a589fabce1cb79ff13a1411302`).
  - [ ] **cosign keyless signing**: `sigstore/cosign-installer` v4.1.2
        (`6f9f17788090df1f26f669e9d70d6ae9567deba6`) with
        `cosign-release: v3.1.3`; sign by digest.
  - [ ] **SLSA provenance**: `actions/attest-build-provenance` v4.2.2
        (`4d101475d8b20a2381f78447822ac1eab6504dd8`).
  - [ ] **SBOM attestation**: `actions/attest-sbom` v4.1.0
        (`c604332985a26aa8cf1bdc465b92731239ec6b9e`) over the SPDX SBOM.
  - [ ] Verification documented and tried once: `cosign verify` with the
        workflow identity, and `gh attestation verify`.
  - Why this waited for the flip: keyless signing writes a permanent entry
    to the public Rekor transparency log. The signing certificate records
    the repository name, workflow path, refs, commit SHAs, run IDs and the
    repository's visibility at signing time. Signing while private would
    have published the repository's existence and its "private" status,
    permanently. GitHub's own attestations are not available on a free
    private repository at all.
- [ ] Make the **GHCR package public**. This is **irreversible**: a public
      package cannot be made private again.
- [ ] Add `image: ghcr.io/tbording/haos-exporter` to `config.yaml`, with
      `version` matching a published tag, and move `image` from
      `FORBIDDEN_KEYS` to `ALLOWED_KEYS` in `ci/check_manifest.py`. Installing from the GitHub
      repository is a different app from the local one (its slug gets the
      repository's prefix instead of `local_`), so this is a **reinstall**:
      uninstall the local app, add the repository, install, and enter the
      options again. The AppArmor profile is loaded under the new slug.
- [ ] **Place the TLS files again under the new slug.** The reinstall gives
      the app a new config folder, `/app_configs/<repo-prefix>_haos_exporter`.
      Generate a new server pair there (DOCS.md, Verified TLS), copy
      `client-ca.crt`, re-pin Prometheus, and delete the old
      `/app_configs/local_haos_exporter`, which survives uninstall and still
      holds the old key.
- [ ] Re-run the whole CI on `main` after all of the above and confirm every
      required check passes.

## 5. Sign-off

- [ ] Every box above is ticked, and the independent review found no open
      issue.

Signed off by: ____________________  Date: ____________
