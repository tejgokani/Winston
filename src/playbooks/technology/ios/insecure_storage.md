---
id: technology.ios.insecure_storage
title: "iOS: Insecure Data Storage & Keychain"
category: technology
vulnerabilityClass: insecure_storage
appliesToStack: ios
requiresAnyTag: ["ios"]
deepOnly: false
reviewPass: 2
owaspRefs:
  - "OWASP MASVS-STORAGE"
  - "A02:2021 Cryptographic Failures"
cweRefs:
  - "CWE-312"
  - "CWE-522"
  - "CWE-311"
realWorldReferences:
  - title: "OWASP MASTG — iOS local storage testing (Keychain, UserDefaults, files, Data Protection)"
    url: "https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/"
    type: security_blog
  - title: "Apple — Keychain Services and Data Protection classes for at-rest security"
    url: "https://developer.apple.com/documentation/security/keychain_services"
    type: vendor_security_advisory
  - title: "Disclosed iOS bugs: credentials/tokens in UserDefaults or unprotected files recoverable from backups/jailbreak"
    url: "https://hackerone.com/reports/1591162"
    type: bug_bounty_disclosure
quickModeSummary: >
  On iOS, secrets belong in the Keychain (with an appropriate accessibility class),
  not in UserDefaults, plist files, Core Data, or plain files — those are
  recoverable from iTunes/iCloud backups, a jailbroken device, or forensic access.
  Flag: auth tokens/passwords/keys stored in UserDefaults or files instead of the
  Keychain; Keychain items with an over-permissive accessibility (kSecAttrAccessible
  Always / AfterFirstUnlock when WhenUnlocked/…ThisDeviceOnly is warranted, or not
  ThisDeviceOnly for secrets that shouldn't sync/backup); sensitive files written
  without Data Protection (NSFileProtectionComplete) so they're readable when the
  device is locked/backed up; hardcoded keys/secrets in the app binary
  (recoverable); and sensitive data in NSLog/os_log. Use the Keychain with the
  strictest workable accessibility, apply Data Protection to files, and keep
  secrets out of logs and out of iCloud backup.
fileSelectionHint:
  roles: ["service", "storage", "model", "auth", "config"]
  matchImports: ["Security", "Foundation", "KeychainAccess", "CoreData", "UserDefaults"]
  matchAuthMapTags: ["ios"]
  maxFiles: 12
  priorityOrder: ["auth", "storage", "service", "model"]
severityHeuristics:
  critical:
    - "Authentication material (tokens, passwords, session/encryption keys) is stored in UserDefaults, a plist, Core Data, or a plain file rather than the Keychain, so it is recoverable from a backup, jailbreak, or forensic access"
  high:
    - "A Keychain item uses an over-permissive accessibility (kSecAttrAccessibleAlways, or a non-ThisDeviceOnly class for a secret that then syncs to iCloud Keychain / is included in backups), broadening where the secret is exposed"
    - "Sensitive files are written without Data Protection (default protection insufficient / NSFileProtectionNone) so they're readable while locked or from backup; or hardcoded secrets/keys sit in the app binary"
  medium:
    - "Sensitive data is in app-sandbox files without encryption where the threat model includes jailbroken/backed-up devices, or accessibility is stricter than Always but looser than needed"
    - "Sensitive data is written to NSLog/os_log or included in iTunes/iCloud backup unnecessarily"
  low:
    - "Secrets in the Keychain with an appropriate ThisDeviceOnly accessibility, files with NSFileProtectionComplete, and no secrets in logs/binary — the target state; confirm the accessibility class and data sensitivity before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:local_storage"
  relatedNodeIds: ["component:secrets", "component:cryptography"]
graphEdgeMapping:
  - relation: exposes
    from: "component:local_storage"
    to: "component:secrets"
  - relation: depends_on
    from: "component:local_storage"
    to: "component:cryptography"
commonAiCodingMistakes:
  - "AI stores the auth token in `UserDefaults` ('the easy persistence') — but UserDefaults is a plist recoverable from backups and jailbreak, so the credential leaks. Secrets belong in the Keychain."
  - "AI writes a Keychain item with `kSecAttrAccessibleAlways` (readable even when locked) or a syncable/backupable class, when `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` is appropriate — broadening exposure."
  - "AI writes sensitive files without Data Protection (NSFileProtectionComplete), so they're readable while the device is locked or restored from backup."
  - "AI hardcodes API keys/secrets in the binary/Info.plist, recoverable by anyone who extracts the app."
  - "AI stores PII/tokens in Core Data / a plain SQLite DB with no encryption."
  - "AI logs tokens/PII via NSLog/os_log, or leaves sensitive app data in iCloud backup."
falsePositiveGuardrails:
  - "Do not flag secrets stored in the Keychain with an appropriate accessibility class (WhenUnlockedThisDeviceOnly for typical secrets) — that is the correct pattern. Confirm the accessibility isn't over-permissive."
  - "Non-sensitive data in UserDefaults/files (preferences, non-secret config) is fine — establish the data is actually sensitive before flagging."
  - "Files protected with NSFileProtectionComplete (encrypted while locked) are correctly protected — only NSFileProtectionNone / unprotected sensitive files are the finding."
  - "Data kept only in the app sandbox on a non-jailbroken device has baseline protection; rate by whether the threat model includes backup/jailbreak/forensic and whether it's excluded from backup."
---

## Root Cause Explanation

iOS gives apps a purpose-built secret store — the **Keychain**, backed by the
Secure Enclave and gated by **accessibility classes** — precisely because the
alternatives (UserDefaults, plists, Core Data, plain files) are all recoverable.
UserDefaults is a plist in the app sandbox; files sit in the sandbox too. Both come
out of an unencrypted iTunes backup, an iCloud backup, or a jailbroken/forensically
-imaged device. So storing tokens, passwords, or keys anywhere but the Keychain is
disclosure waiting for device or backup access. Even within the Keychain,
**accessibility** matters: `kSecAttrAccessibleAlways` keeps a secret readable while
the device is locked, and non-`ThisDeviceOnly` classes let it sync to iCloud
Keychain and enter backups — broadening exposure beyond the device.

Files that must hold sensitive data need **Data Protection**
(`NSFileProtectionComplete`), which ties their encryption to the device being
unlocked. And secrets hardcoded in the binary/Info.plist are simply extractable.
The controls: put secrets in the Keychain with the strictest workable accessibility
(commonly `WhenUnlockedThisDeviceOnly`), apply Data Protection to sensitive files,
keep secrets out of logs and the app binary, and exclude sensitive data from iCloud
backup.

## Vulnerable Patterns

```swift
// Credential in UserDefaults — recoverable from backup/jailbreak
UserDefaults.standard.set(authToken, forKey: "auth_token")

// Over-permissive Keychain accessibility
let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                        kSecAttrAccessible as String: kSecAttrAccessibleAlways]  // too broad

// Sensitive file with no Data Protection
try data.write(to: url, options: [])                                            // NSFileProtectionNone
NSLog("token=\(authToken)")                                                     // logged
```

Correct: Keychain + strict accessibility + Data Protection.

```swift
let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
  kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
  kSecValueData as String: tokenData]
SecItemAdd(q as CFDictionary, nil)
try data.write(to: url, options: [.completeFileProtection])
```

## Data Flow Tracing Guide

1. Find sensitive data (tokens, passwords, keys, PII) and its storage: Keychain,
   UserDefaults, plists, Core Data, files.
2. For Keychain items, check the accessibility class (over-permissive? syncable/
   backupable when it shouldn't be?).
3. For files, check Data Protection level (NSFileProtectionComplete vs. none).
4. Grep the binary/Info.plist for hardcoded secrets; grep NSLog/os_log for
   sensitive data.
5. Check iCloud backup inclusion for sensitive data.

## Evidence Checklist

- [ ] The sensitive data and its storage mechanism, quoted.
- [ ] Keychain accessibility class or the non-Keychain location.
- [ ] File Data Protection level.
- [ ] Hardcoded secrets / logged secrets if present.

## Attack Scenario Template

> An attacker with [an iTunes/iCloud backup / a jailbroken or stolen device] reads
> [file:line]'s storage. Because the [token/PII/key] is stored [in UserDefaults / a
> plain file / the Keychain with kSecAttrAccessibleAlways], the attacker recovers
> it, resulting in [account takeover / data disclosure].

## Graph Mapping Instructions

- Ensure a `component:local_storage` node with an `exposes` edge to
  `component:secrets` and a `depends_on` edge to `component:cryptography`.
- Credential findings are account-takeover class — note it in `reasoning`.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:local_storage`.
