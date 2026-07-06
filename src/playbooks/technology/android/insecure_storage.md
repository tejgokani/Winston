---
id: technology.android.insecure_storage
title: "Android: Insecure Data Storage"
category: technology
vulnerabilityClass: insecure_storage
appliesToStack: android
requiresAnyTag: ["android"]
deepOnly: false
reviewPass: 2
owaspRefs:
  - "OWASP MASVS-STORAGE"
  - "A02:2021 Cryptographic Failures"
cweRefs:
  - "CWE-312"
  - "CWE-522"
  - "CWE-921"
realWorldReferences:
  - title: "OWASP MASVS/MASTG — testing for sensitive data in local storage on Android"
    url: "https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/"
    type: security_blog
  - title: "Android — EncryptedSharedPreferences / Jetpack Security and the Keystore for at-rest protection"
    url: "https://developer.android.com/topic/security/data"
    type: vendor_security_advisory
  - title: "Disclosed mobile bugs: tokens/PII stored in plaintext SharedPreferences and world-readable files"
    url: "https://hackerone.com/reports/1591162"
    type: bug_bounty_disclosure
quickModeSummary: >
  Data written to device storage is recoverable — by anyone with the (backed-up,
  rooted, or forensically-imaged) device, and historically by other apps. Flag
  sensitive data (auth tokens, passwords, PII, keys, session data) stored in
  plaintext in SharedPreferences, in files on internal/external storage, in a
  local SQLite/Room database, or in logs, without encryption. Prefer
  EncryptedSharedPreferences / the Android Keystore (hardware-backed) for secrets;
  never write sensitive data to external/shared storage; keep it out of logs and
  out of `allowBackup` scope. Also flag hardcoded keys/credentials in the APK
  (decompilable), MODE_WORLD_READABLE/WRITABLE usage, and secrets in
  SharedPreferences "encrypted" with a key that's also in the APK. Store the
  minimum, encrypt what must persist with Keystore-backed keys, and exclude it
  from backups.
fileSelectionHint:
  roles: ["service", "storage", "model", "config", "auth"]
  matchImports: ["android", "androidx.security", "SharedPreferences", "SQLiteDatabase", "androidx.room"]
  matchAuthMapTags: ["android"]
  maxFiles: 12
  priorityOrder: ["auth", "storage", "service", "model"]
severityHeuristics:
  critical:
    - "Authentication material (tokens, passwords, session keys, encryption keys) is stored in plaintext in SharedPreferences, files, or a local database, so anyone with device access (backup, rooted, stolen, forensic) recovers it"
    - "Sensitive data is written to EXTERNAL/shared storage (readable by other apps / anyone with the device) in plaintext"
  high:
    - "PII or other sensitive data is persisted unencrypted in local storage, or secrets are 'encrypted' with a key hardcoded in the APK (trivially recovered by decompilation)"
    - "Sensitive data (tokens, PII) is written to logcat / log files, or included in `allowBackup` so it leaves the device in cloud backups"
  medium:
    - "Sensitive data uses app-internal storage without encryption but the threat model includes rooted/backed-up devices, or MODE_WORLD_* legacy modes are used"
    - "Encryption is present but the key management is weak (not Keystore-backed) or inconsistent across the app"
  low:
    - "Non-sensitive data in internal storage, or sensitive data protected by EncryptedSharedPreferences/Keystore and excluded from backup — the target state; confirm the data's sensitivity and protection before dismissing"
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
  - "AI stores the auth token/session in plaintext `SharedPreferences` ('the easy key-value store'), so a rooted device, an ADB backup, or a stolen phone yields the credential — the most common Android storage bug."
  - "AI writes sensitive files (downloads, exports, caches with PII) to external/shared storage, which is readable by other apps (pre-scoped-storage) or anyone with the device."
  - "AI stores PII/tokens in a local SQLite/Room database with no encryption (no SQLCipher / EncryptedSharedPreferences)."
  - "AI hardcodes an API key or encryption key in the app and 'encrypts' storage with it — the APK is decompilable, so the key is recoverable and the encryption is theater."
  - "AI logs tokens/PII via `Log.d`, leaving them in logcat / log files."
  - "AI leaves `android:allowBackup=\"true\"` so sensitive app data is included in cloud/ADB backups off-device."
falsePositiveGuardrails:
  - "Do not flag sensitive data protected by EncryptedSharedPreferences or Android Keystore-backed encryption and kept in internal storage — that is the correct pattern. Confirm the key is Keystore-backed (not hardcoded)."
  - "Non-sensitive data (UI preferences, non-secret config) in plaintext internal storage is fine — establish the data is actually sensitive (auth/PII/keys) before flagging."
  - "Data in app-internal storage (not external/world-readable) is protected from other apps on modern Android; rate it by whether the threat model includes rooted/backed-up/stolen devices and whether it's excluded from backup."
  - "Encryption with a Keystore-generated key (hardware-backed where available) is correct even if data persists — only hardcoded-key or absent encryption is the finding."
---

## Root Cause Explanation

Anything an app writes to the device can be read back by someone who has the
device — through an ADB/cloud backup, a rooted phone, a stolen or lost device, or
forensic imaging — and historically by other apps sharing external storage. So
storing sensitive data (auth tokens, passwords, session keys, PII, encryption
keys) in plaintext is disclosure waiting for device access. The Android-specific
traps are `SharedPreferences` used as a plaintext credential store (it's just an
XML file), sensitive files on **external/shared** storage (broadly readable),
local SQLite/Room databases without encryption, and secrets in logcat. A special
non-fix is "encrypting" storage with a key hardcoded in the APK: the APK
decompiles, the key falls out, and the encryption protects nothing.

The controls are: store the **minimum**; for secrets that must persist, use
**EncryptedSharedPreferences** or the **Android Keystore** (hardware-backed keys
that never leave secure hardware); keep sensitive data out of external storage and
out of logs; and exclude it from backups (`allowBackup=false` or backup rules).
Encryption is only as good as its key management — the key must be Keystore-backed,
not shipped in the app.

## Vulnerable Patterns

```kotlin
// Plaintext credential in SharedPreferences
prefs.edit().putString("auth_token", token).apply()               // recoverable

// Sensitive file on external/shared storage
File(getExternalFilesDir(null), "secrets.json").writeText(json)   // broadly readable

Log.d("auth", "token=$token")                                     // in logcat
// AndroidManifest: android:allowBackup="true"                    // leaves device
```

Correct: Keystore-backed encryption, internal storage, no logs, no backup.

```kotlin
val prefs = EncryptedSharedPreferences.create(
  context, "secure", MasterKey.Builder(context).setKeyScheme(AES256_GCM).build(),
  PrefKeyEncryptionScheme.AES256_SIV, PrefValueEncryptionScheme.AES256_GCM)
prefs.edit().putString("auth_token", token).apply()               // Keystore-backed
```

## Data Flow Tracing Guide

1. Find sensitive data (tokens, passwords, keys, PII) and where it's persisted:
   SharedPreferences, files (internal vs. external), SQLite/Room, logs.
2. Check encryption: EncryptedSharedPreferences/Keystore vs. plaintext vs.
   hardcoded-key "encryption".
3. Flag anything sensitive on external/shared storage or in logcat.
4. Check `allowBackup` / backup rules for sensitive data leaving the device.
5. Grep the APK sources for hardcoded keys/credentials.

## Evidence Checklist

- [ ] The sensitive data and its storage location/mechanism, quoted.
- [ ] The encryption (or its absence / hardcoded key).
- [ ] External-storage or logcat exposure if present.
- [ ] `allowBackup` status for sensitive data.

## Attack Scenario Template

> An attacker with [an ADB/cloud backup / a rooted or stolen device] reads
> [file:line]'s storage. Because the [token/PII/key] is stored [in plaintext
> SharedPreferences / on external storage / encrypted with an APK-hardcoded key],
> the attacker recovers it, resulting in [account takeover / data disclosure].

## Graph Mapping Instructions

- Ensure a `component:local_storage` node with an `exposes` edge to
  `component:secrets` (for credentials) and a `depends_on` edge to
  `component:cryptography`.
- Credential-storage findings are account-takeover class — note it in `reasoning`.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:local_storage`.
