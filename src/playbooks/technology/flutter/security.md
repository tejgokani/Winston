---
id: technology.flutter.security
title: "Flutter: Platform Channels, Storage & TLS"
category: technology
vulnerabilityClass: insecure_mobile_practice
appliesToStack: flutter
requiresAnyTag: ["flutter"]
deepOnly: false
reviewPass: 2
owaspRefs:
  - "OWASP MASVS-STORAGE"
  - "OWASP MASVS-NETWORK"
  - "A02:2021 Cryptographic Failures"
cweRefs:
  - "CWE-312"
  - "CWE-295"
  - "CWE-749"
realWorldReferences:
  - title: "OWASP MASTG — applicable storage/network tests for cross-platform (Flutter) apps"
    url: "https://mas.owasp.org/MASTG/"
    type: security_blog
  - title: "Flutter — secure storage (flutter_secure_storage → Keychain/Keystore) vs. SharedPreferences"
    url: "https://pub.dev/packages/flutter_secure_storage"
    type: security_blog
  - title: "Disabling TLS validation in Dart/Flutter (badCertificateCallback => true) enabling MITM"
    url: "https://api.flutter.dev/flutter/dart-io/HttpClient/badCertificateCallback.html"
    type: vendor_security_advisory
quickModeSummary: >
  Flutter apps face the same mobile risks as native, plus a platform-channel bridge
  to native code. Flag: secrets stored via shared_preferences (plaintext, like
  Android SharedPreferences / iOS UserDefaults) instead of flutter_secure_storage
  (which uses Keystore/Keychain); TLS validation disabled — HttpClient
  badCertificateCallback returning true, or a permissive SecurityContext — enabling
  MITM; hardcoded secrets/keys in Dart (compiled but extractable) or in the bundled
  assets; platform-channel (MethodChannel) handlers on the native side that act on
  Dart-supplied arguments without validation (reaching native file/shell/SQL sinks);
  and sensitive data in debugPrint/logs. Use flutter_secure_storage for secrets, keep
  TLS validation intact (pin for sensitive apps), validate platform-channel arguments
  on the native side, and keep secrets out of the bundle and logs.
fileSelectionHint:
  roles: ["service", "storage", "network", "channel", "config"]
  matchImports: ["flutter_secure_storage", "shared_preferences", "http", "dio", "dart:io"]
  matchAuthMapTags: ["flutter"]
  maxFiles: 12
  priorityOrder: ["network", "storage", "channel", "service"]
severityHeuristics:
  critical:
    - "TLS validation is disabled — HttpClient.badCertificateCallback returns true, or a permissive SecurityContext accepts any cert — so a network MITM intercepts and modifies all traffic including credentials"
    - "A native platform-channel handler passes Dart-supplied arguments into a native sink (shell/exec, file path, SQL) without validation, reachable from the Dart side (or an injected context)"
  high:
    - "Secrets (tokens, keys, passwords) are stored via shared_preferences (plaintext) instead of flutter_secure_storage, recoverable from backup/rooted/jailbroken devices"
    - "Secrets/keys are hardcoded in Dart source or bundled assets (extractable from the app), or sensitive data is transmitted over cleartext HTTP"
  medium:
    - "Sensitive data uses insecure storage where the threat model includes rooted/backed-up devices, or a high-value app lacks certificate pinning where warranted"
    - "Platform-channel arguments are partially validated, or sensitive data is written to debugPrint/logs"
  low:
    - "Secrets in flutter_secure_storage, intact TLS validation (pinning where appropriate), validated platform-channel handlers, and no secrets in bundle/logs — the target state; confirm before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:mobile_platform"
  relatedNodeIds: ["component:secrets", "component:network_transport"]
graphEdgeMapping:
  - relation: exposes
    from: "component:mobile_platform"
    to: "component:secrets"
  - relation: depends_on
    from: "component:mobile_platform"
    to: "component:network_transport"
commonAiCodingMistakes:
  - "AI stores the auth token in `shared_preferences`, which is plaintext (Android SharedPreferences / iOS UserDefaults under the hood) — secrets belong in `flutter_secure_storage` (Keystore/Keychain-backed)."
  - "AI sets `httpClient.badCertificateCallback = (cert, host, port) => true` (usually to accept a dev cert) — disabling TLS validation so any MITM reads/modifies traffic."
  - "AI hardcodes API keys/secrets in Dart or in bundled assets, which are extractable from the compiled app."
  - "AI writes a native MethodChannel handler that uses Dart-supplied arguments in a native file/shell/SQL operation without validating them."
  - "AI sends sensitive data over HTTP, or leaves sensitive data in `debugPrint`/logs."
  - "AI handles high-value data with no certificate pinning where the threat model warrants it."
falsePositiveGuardrails:
  - "Do not flag secrets stored via flutter_secure_storage (Keystore/Keychain-backed) — that is the correct pattern. Only shared_preferences (or plaintext files) for secrets is a finding."
  - "Default Dart/Flutter HTTP with intact TLS validation is correct — only badCertificateCallback=>true or a permissive SecurityContext is the finding."
  - "Non-sensitive data in shared_preferences (UI prefs) is fine — establish sensitivity before flagging."
  - "Platform-channel handlers that validate/allow-list Dart-supplied arguments before native sinks are correct — the concern is unvalidated arguments reaching a sink."
  - "Cross-reference the android/ios storage & network playbooks — for a Flutter app those platform behaviors apply too; report the Flutter-idiomatic gaps here without double-counting."
---

## Root Cause Explanation

Flutter compiles to native apps, so it inherits the full mobile threat model —
insecure local storage, weak transport security, extractable secrets — expressed
through Dart idioms, plus one extra bridge: **platform channels** (`MethodChannel`)
that pass data between Dart and native code. The recurring Dart-flavored mistakes
map directly onto the native ones. `shared_preferences` is a plaintext store (backed
by Android `SharedPreferences` / iOS `UserDefaults`), so putting secrets there is the
same disclosure bug as on native — the fix is `flutter_secure_storage`, which uses the
Keystore/Keychain. TLS validation is disabled with a single infamous line,
`badCertificateCallback = (c, h, p) => true`, which accepts any certificate and hands
all traffic to a MITM. Secrets hardcoded in Dart or bundled assets are extractable
from the compiled app.

The Flutter-specific surface is the platform channel: native handlers receive
arguments from the Dart side and, if they forward them into native file/shell/SQL
operations without validation, reintroduce injection on the native side (and the Dart
side may itself be influenced by untrusted input). The controls are the mobile
standards applied through Flutter: `flutter_secure_storage` for secrets, intact TLS
validation (with pinning for sensitive apps), validated platform-channel arguments on
the native side, and no secrets in the bundle or logs. Cross-reference the Android/iOS
storage and network playbooks for the underlying platform behaviors.

## Vulnerable Patterns

```dart
// Secret in plaintext shared_preferences
final prefs = await SharedPreferences.getInstance();
await prefs.setString('auth_token', token);                 // plaintext

// TLS validation disabled — MITM accepted
httpClient.badCertificateCallback = (cert, host, port) => true;

const apiKey = 'sk_live_hardcoded';                          // extractable from the app
```

Correct: secure storage, intact TLS, validated channels.

```dart
const storage = FlutterSecureStorage();
await storage.write(key: 'auth_token', value: token);        // Keystore/Keychain
// no badCertificateCallback override; pin for sensitive apps
```

## Data Flow Tracing Guide

1. Find secret storage: shared_preferences/files (plaintext) vs. flutter_secure_storage.
2. Search for `badCertificateCallback`/permissive SecurityContext and cleartext HTTP.
3. Grep Dart and bundled assets for hardcoded secrets/keys.
4. Review native MethodChannel handlers: trace Dart-supplied arguments into native
   file/shell/SQL sinks; check validation.
5. Check debugPrint/logs for sensitive data; check pinning for high-value apps.

## Evidence Checklist

- [ ] Secret storage mechanism, quoted.
- [ ] Any TLS-validation bypass, quoted.
- [ ] Hardcoded secrets in Dart/assets.
- [ ] Platform-channel handler sinks and validation.

## Attack Scenario Template

> An attacker [MITMs the network / recovers the device backup / extracts the app
> bundle]. Because [file:line] [disables TLS validation / stores the token in
> shared_preferences / hardcodes the key / forwards channel args to a native sink],
> the attacker [intercepts traffic / recovers the credential / extracts the key /
> reaches native injection], resulting in [account compromise / data theft].

## Graph Mapping Instructions

- Ensure a `component:mobile_platform` node with an `exposes` edge to
  `component:secrets` and a `depends_on` edge to `component:network_transport`.
- Platform-channel injection findings add a `causes` edge toward the native sink.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:mobile_platform`; cross-link to android/ios storage & network.
