---
id: technology.mobile.permissions_privacy
title: "Mobile: Permissions & Privacy"
category: technology
vulnerabilityClass: privacy_violation
appliesToStack: mobile apps requesting device permissions / handling personal data
requiresAnyTag: ["android", "ios", "flutter", "expo"]
deepOnly: true
reviewPass: 3
owaspRefs:
  - "OWASP MASVS-PRIVACY"
  - "A01:2021 Broken Access Control"
cweRefs:
  - "CWE-250"
  - "CWE-359"
  - "CWE-200"
realWorldReferences:
  - title: "OWASP MASVS-PRIVACY — data minimization, permission justification, and third-party data flows"
    url: "https://mas.owasp.org/MASVS/12-MASVS-PRIVACY/"
    type: security_blog
  - title: "Apple — Privacy manifests, required-reason APIs, and App Tracking Transparency"
    url: "https://developer.apple.com/documentation/bundleresources/privacy_manifest_files"
    type: vendor_security_advisory
  - title: "Android — permission best practices, foreground/background location, and the photo picker over broad storage access"
    url: "https://developer.android.com/guide/topics/permissions/overview"
    type: vendor_security_advisory
quickModeSummary: >
  Over-broad permissions and unnecessary data collection are both a security blast-
  radius issue and a compliance/store-rejection issue. Review requested permissions
  (AndroidManifest uses-permission, iOS Info.plist usage keys, Expo plugins): flag
  dangerous/sensitive permissions requested beyond what features need — background
  location, full contacts, all-photos/broad storage, microphone/camera, SMS/call log,
  device identifiers — since each is data an attacker gains if the app is compromised
  and a privacy liability. Flag: sensitive permissions with no clear feature need;
  broad storage/photo access where a scoped picker suffices; collecting/transmitting
  personal data or device identifiers to third parties (SDKs) without disclosure/
  consent; missing iOS privacy manifest / usage-description strings; and persistent
  identifiers used for tracking without consent (ATT). Request the minimum, use scoped
  pickers, disclose and gate third-party data sharing, and prefer non-identifying
  approaches.
fileSelectionHint:
  roles: ["config", "service", "controller"]
  matchImports: ["android", "expo", "react-native-permissions", "permission_handler"]
  matchAuthMapTags: ["android", "ios", "flutter", "expo"]
  maxFiles: 10
  priorityOrder: ["config", "service", "controller"]
severityHeuristics:
  critical:
    - "The app collects and transmits sensitive personal data (precise location, contacts, health, identifiers) to a third party / SDK without disclosure or consent, or to an endpoint that retains it — a privacy breach and likely legal/compliance violation"
  high:
    - "Sensitive/dangerous permissions (background location, full contacts, all-photos, microphone, SMS/call log, persistent device identifiers) are requested with no corresponding feature need, expanding both the compromise blast radius and privacy exposure"
    - "Personal data or identifiers are used for cross-app tracking without consent (no ATT on iOS / no consent where required)"
  medium:
    - "Broad storage/photo access is used where a scoped picker (Android Photo Picker / iOS PHPicker) would suffice, or permissions are requested up front rather than in context at point of use"
    - "iOS privacy manifest / required-reason API declarations or usage-description strings are missing/inaccurate"
  low:
    - "Minimal, feature-justified permissions requested in context, scoped pickers, disclosed and consented third-party sharing, and accurate privacy manifests — the target state; confirm permission-to-feature mapping before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:privacy_surface"
  relatedNodeIds: ["component:data_store", "component:external_system"]
graphEdgeMapping:
  - relation: exposes
    from: "component:privacy_surface"
    to: "component:external_system"
commonAiCodingMistakes:
  - "AI requests broad permissions 'in case they're needed' (background location, full contacts, all-photos, microphone) that the features don't use — each is sensitive data an attacker gets if the app is compromised, and a store-rejection/compliance risk."
  - "AI sends personal data or device identifiers to analytics/ad SDKs without disclosure or consent, creating a privacy breach and legal exposure."
  - "AI uses broad storage/all-photos access to pick one image, where the scoped Photo Picker / PHPicker needs no permission at all."
  - "AI requests all permissions at launch rather than in context when the feature is used, and without clear rationale."
  - "AI omits the iOS privacy manifest / required-reason API declarations or the Info.plist usage-description strings, or writes inaccurate ones."
  - "AI uses a persistent identifier for tracking without App Tracking Transparency / consent where required."
falsePositiveGuardrails:
  - "Do not flag permissions that clearly map to a used feature (camera for a scanner, location for a maps feature with foreground-only scope) — judge each permission against actual functionality and prefer the narrowest scope (foreground vs. background location, scoped picker vs. broad storage)."
  - "Third-party data sharing that is disclosed and consented (privacy policy + in-app consent, ATT where required) is a business/compliance decision, not automatically a vulnerability — flag undisclosed/unconsented sharing of sensitive data."
  - "Scoped pickers (Android Photo Picker, iOS PHPicker) that need no broad permission are the correct minimal pattern."
  - "Accurate privacy manifests and in-context permission requests are correct — only missing/inaccurate declarations or up-front over-requests are findings."
  - "This is a deep-mode, privacy-focused pass — rank concrete sensitive-data-to-third-party flows above manifest-hygiene items."
---

## Root Cause Explanation

Every permission a mobile app holds and every piece of personal data it collects is
both an **attack blast-radius** and a **privacy/compliance** exposure. If the app is
compromised (a malicious SDK, a supply-chain issue, a stolen device), an attacker
inherits exactly the permissions and data the app accumulated — so background
location, full contacts, all-photos access, microphone, and persistent identifiers
requested "just in case" become the attacker's reach. Independently, collecting or
sharing personal data without disclosure and consent is a legal violation (GDPR/CCPA)
and a common cause of App Store / Play rejection, especially with iOS privacy
manifests, required-reason APIs, and App Tracking Transparency now enforced.

The governing principle is **data and permission minimization**: request only the
permissions a shipped feature needs, at the narrowest scope (foreground vs. background
location; scoped photo/media pickers that need no permission at all rather than broad
storage), in context at the point of use; disclose and gate any third-party data
sharing; declare privacy manifests and usage strings accurately; and avoid
identifying/tracking data without consent. Less collected is less to leak and less to
answer for.

## Vulnerable Patterns

```xml
<!-- Android: broad, unjustified sensitive permissions -->
<uses-permission android:name="android.permission.ACCESS_BACKGROUND_LOCATION"/>
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>   <!-- for one photo -->
```

```js
// Personal data / identifier to a third-party SDK without consent
analytics.track({ userId, email, deviceId, preciseLocation });   // undisclosed
```

Correct: minimal, scoped, in-context, disclosed.

```kotlin
// Scoped photo picker needs no broad storage permission
val picker = registerForActivityResult(PickVisualMedia()) { uri -> /* one photo */ }
// request location foreground-only, in context, with rationale
```

## Data Flow Tracing Guide

1. List requested permissions (AndroidManifest uses-permission, iOS Info.plist usage
   keys, Expo/plugin config) and map each to a shipped feature; flag unjustified ones.
2. Flag broad/background/sensitive scopes where narrower (foreground, scoped picker)
   would work.
3. Trace personal data and device identifiers into third-party SDKs/endpoints; check
   disclosure and consent.
4. Check iOS privacy manifest, required-reason API declarations, usage-description
   strings, and ATT where identifiers are used for tracking.
5. Check whether permissions are requested in context vs. up front.

## Evidence Checklist

- [ ] The requested permissions vs. the features that use them.
- [ ] Any sensitive personal-data/identifier flow to a third party and its consent
      status.
- [ ] Scope choices (background vs. foreground, broad storage vs. scoped picker).
- [ ] Privacy manifest / usage-string / ATT status.

## Attack Scenario Template

> [The app is compromised (malicious SDK / device access) / the app shares data
> undisclosed]. Because [file:line] holds [background location / full contacts /
> all-photos] with no feature need, or transmits [personal data/identifiers] to
> [a third party] without consent, the result is [the attacker inheriting sensitive
> data / a privacy breach and compliance violation].

## Graph Mapping Instructions

- Ensure a `component:privacy_surface` node; third-party data flows add an `exposes`
  edge to `component:external_system`.
- Note the minimization/compliance rationale in `reasoning`.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:privacy_surface`.
