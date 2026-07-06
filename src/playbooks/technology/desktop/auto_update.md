---
id: technology.desktop.auto_update
title: "Desktop: Auto-Update Integrity"
category: technology
vulnerabilityClass: integrity_failure
appliesToStack: desktop apps with auto-update (Electron/Tauri/Squirrel/Sparkle)
requiresAnyTag: ["electron", "tauri"]
deepOnly: false
reviewPass: 2
owaspRefs:
  - "A08:2021 Software and Data Integrity Failures"
  - "A05:2021 Security Misconfiguration"
cweRefs:
  - "CWE-494"
  - "CWE-345"
  - "CWE-319"
realWorldReferences:
  - title: "Sparkle (macOS) insecure update over HTTP enabling MITM code execution (CVE-2016-... 'Sparkle Updater' class)"
    url: "https://vulnsec.com/2016/osx-apps-vulnerabilities/"
    type: research_paper
  - title: "Electron autoUpdater / electron-updater — signature verification and HTTPS requirements"
    url: "https://www.electronjs.org/docs/latest/tutorial/updates"
    type: security_blog
  - title: "Tauri updater — required signature (minisign) verification of update artifacts"
    url: "https://tauri.app/plugin/updater/"
    type: vendor_security_advisory
quickModeSummary: >
  An auto-updater downloads code and runs it with the app's (often elevated)
  privileges, so it is a direct code-execution channel — and if the update isn't
  authenticated, a network attacker (MITM) or a compromised update host ships
  malware to every user. Check that updates are: served over HTTPS (never plain
  HTTP), and cryptographically signature-verified against a pinned public key
  BEFORE install (Tauri's minisign, Electron code signing + electron-updater's
  verification, Sparkle EdDSA). Flag update feeds over HTTP, disabled/absent
  signature verification, update URLs that are user/config-controllable, and
  unsigned artifacts. The update mechanism must trust nothing it downloads until
  the signature checks out against a key baked into the app.
fileSelectionHint:
  roles: ["config", "main", "service", "infra"]
  matchImports: ["electron-updater", "electron", "@tauri-apps/api"]
  matchAuthMapTags: ["electron", "tauri"]
  maxFiles: 10
  priorityOrder: ["config", "main", "service"]
severityHeuristics:
  critical:
    - "Updates are fetched over plain HTTP, or update artifacts are installed without cryptographic signature verification against a pinned key — a MITM or compromised host can deliver arbitrary code that runs with the app's privileges (mass RCE)"
  high:
    - "Signature verification exists but the trusted key/endpoint is configurable at runtime, or the verification can be disabled, so the trust anchor can be subverted"
    - "The update URL/feed is user- or config-controllable, letting an attacker point the app at a malicious update source"
  medium:
    - "Updates are over HTTPS with signature verification, but the downloaded artifact is handled insecurely before verification (written to a world-writable path, or verified after partial execution), or channel/rollback protection is missing (downgrade attacks)"
    - "The updater runs with more privilege than needed for the install step"
  low:
    - "HTTPS + pinned-key signature verification before install with a non-configurable trust anchor — the target state; confirm the verification runs pre-install before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:auto_update"
  relatedNodeIds: ["component:remote_code_execution", "component:external_system"]
graphEdgeMapping:
  - relation: causes
    from: "component:auto_update"
    to: "component:remote_code_execution"
commonAiCodingMistakes:
  - "AI points the updater at an HTTP (not HTTPS) feed, so a network attacker can MITM the update and deliver malware that runs as the app."
  - "AI ships updates without code signing / signature verification (or disables it during development and never re-enables), so any downloaded artifact is trusted and executed."
  - "AI makes the update URL or the trusted public key configurable at runtime, letting an attacker or a config compromise redirect updates to a malicious source."
  - "AI verifies the signature AFTER writing/executing part of the artifact, or to a world-writable staging path, allowing a race/substitution."
  - "AI omits downgrade/rollback protection, letting an attacker force-install a known-vulnerable older signed version."
falsePositiveGuardrails:
  - "Do not flag an updater that fetches over HTTPS and verifies a cryptographic signature against a public key baked into the app BEFORE install (Tauri minisign, electron-updater with code signing, Sparkle EdDSA) — that is the correct pattern. Confirm the verification is pre-install and the key is pinned."
  - "A configurable update URL that still requires a signature from a pinned, non-configurable key is acceptable — the trust anchor is the key, not the URL; only a configurable/absent key is the finding."
  - "Framework-default updaters with signing enabled are secure — verify signing is actually configured rather than assuming it's off."
  - "Downgrade protection and privilege minimization are hardening; rate them below the core HTTP/no-signature findings."
---

## Root Cause Explanation

An auto-updater is a self-inflicted remote code execution channel: it downloads a
binary and runs it with the application's privileges, on every user's machine,
automatically. That is exactly what an attacker wants, so the only thing standing
between "convenient updates" and "mass malware distribution" is **authenticating
the update before running it**. Two failures open the channel. **Transport**:
fetching updates over plain HTTP lets a network attacker (public Wi-Fi, a
compromised router, a hostile ISP) MITM the download and substitute malware — the
classic Sparkle-over-HTTP break. **Integrity**: installing an artifact without
verifying a cryptographic signature against a key *baked into the app* means a
compromised update host — or that same MITM — can ship anything.

The correct design is non-negotiable and well-supported: serve updates over
HTTPS, and verify a signature against a **pinned** public key **before**
installing (Tauri requires minisign signatures; electron-updater relies on code
signing; Sparkle uses EdDSA). The trust anchor must be the embedded key, not a
URL or a runtime-configurable value, and verification must complete before any
part of the artifact is trusted or executed. Add downgrade protection so an
attacker can't force a signed-but-vulnerable old version.

## Vulnerable Patterns

```js
// HTTP update feed — MITM delivers malware
autoUpdater.setFeedURL({ url: "http://updates.example.com/latest" });   // not HTTPS

// Signature verification disabled / absent — any artifact trusted
autoUpdater.on("update-downloaded", () => autoUpdater.quitAndInstall()); // no verify step
```

```jsonc
// Tauri — configurable pubkey / no signature requirement
{ "updater": { "endpoints": ["http://..."], "pubkey": "" } }
```

Correct: HTTPS + pinned-key signature verification before install.

```jsonc
{ "updater": { "endpoints": ["https://updates.example.com/{{target}}/{{current_version}}"],
               "pubkey": "<baked-in minisign public key>" } }
```

## Data Flow Tracing Guide

1. Find the update feed URL(s) — HTTPS or HTTP?
2. Find the signature/verification configuration — is a pinned public key
   verified before install, or is verification absent/disabled/configurable?
3. Check whether the update URL and trusted key are hardcoded or
   runtime/config-controllable.
4. Check the install sequence: is verification complete before any execution, and
   is the staging path protected?
5. Check for downgrade/rollback protection and updater privilege.

## Evidence Checklist

- [ ] The update feed URL (protocol), quoted.
- [ ] The signature-verification config and the trust anchor (pinned vs.
      configurable/absent).
- [ ] The verify-before-install ordering.
- [ ] Downgrade protection status.

## Attack Scenario Template

> An attacker [MITMs the HTTP update feed / compromises the update host / points
> the configurable update URL at their server]. Because [file:line] [fetches over
> HTTP / installs without signature verification against a pinned key], the app
> downloads and runs the attacker's artifact with the app's privileges, resulting
> in remote code execution on every updating user's machine.

## Graph Mapping Instructions

- Ensure a `component:auto_update` node with a `causes` edge to
  `component:remote_code_execution`.
- Note the mass-distribution blast radius in `reasoning`.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:auto_update`.
