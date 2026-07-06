---
id: technology.mobile.clipboard_and_screen_capture
title: "Mobile/Desktop: Clipboard & Screen Capture Leakage"
category: technology
vulnerabilityClass: sensitive_data_exposure
appliesToStack: mobile/desktop apps handling sensitive on-screen or clipboard data
requiresAnyTag: ["android", "ios", "flutter", "expo", "electron"]
deepOnly: true
reviewPass: 3
owaspRefs:
  - "OWASP MASVS-STORAGE"
  - "OWASP MASVS-PLATFORM"
cweRefs:
  - "CWE-200"
  - "CWE-1230"
  - "CWE-359"
realWorldReferences:
  - title: "OWASP MASTG — testing for sensitive data in the clipboard and via screenshots/backgrounding"
    url: "https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0055/"
    type: security_blog
  - title: "iOS 14+ clipboard-access notifications revealed apps snooping the shared pasteboard"
    url: "https://www.theverge.com/2020/7/10/21319997/apple-ios-14-privacy-clipboard-access-notifications-tiktok"
    type: incident_postmortem
  - title: "Android FLAG_SECURE / iOS backgrounding snapshot — preventing sensitive screens from being captured"
    url: "https://developer.android.com/reference/android/view/WindowManager.LayoutParams#FLAG_SECURE"
    type: vendor_security_advisory
quickModeSummary: >
  Sensitive data leaves the app through two easily-overlooked side channels. (1)
  Clipboard: copying secrets (passwords, tokens, MFA codes, card numbers) to the
  system clipboard exposes them to every other app (the shared pasteboard) and to
  clipboard-sync/history features — flag copying sensitive values, and prefer not
  offering copy for them (or clearing/expiring the clipboard and marking it
  sensitive where supported). (2) Screen capture: the OS captures a snapshot of the
  app when it backgrounds (shown in the app switcher) and users/other apps can
  screenshot or screen-record — sensitive screens should set FLAG_SECURE (Android) /
  obscure the snapshot on backgrounding (iOS) and, for high-value apps, discourage
  screenshots. Flag sensitive data copyable to the clipboard and sensitive screens
  (credentials, tokens, financial/health data) that aren't protected from snapshot/
  screenshot capture.
fileSelectionHint:
  roles: ["view", "controller", "service"]
  matchImports: ["Clipboard", "UIPasteboard", "ClipboardManager", "flutter/services", "expo-clipboard"]
  matchAuthMapTags: ["android", "ios", "flutter", "electron"]
  maxFiles: 10
  priorityOrder: ["view", "controller", "service"]
severityHeuristics:
  high:
    - "Highly sensitive secrets (passwords, auth/session tokens, MFA/OTP codes, full card numbers, private keys) are copied to the system clipboard, exposing them to every other app and to clipboard history/sync"
    - "Screens displaying credentials or high-value sensitive data are not protected from capture (no FLAG_SECURE on Android / no backgrounding-snapshot obfuscation on iOS), so the app-switcher snapshot or a screenshot/recording leaks them"
  medium:
    - "Sensitive-but-lower-value data is placed on the clipboard without marking it sensitive / clearing it, or sensitive screens allow screenshots where the threat model warrants prevention"
    - "Auto-fill/paste flows keep secrets on the clipboard longer than necessary"
  low:
    - "Sensitive screens use FLAG_SECURE / snapshot obfuscation and secrets are not copied to a shared clipboard (or are marked sensitive and cleared) — the target state; confirm the protection covers the sensitive views before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:ui_data_exposure"
  relatedNodeIds: ["component:secrets"]
graphEdgeMapping:
  - relation: exposes
    from: "component:ui_data_exposure"
    to: "component:secrets"
commonAiCodingMistakes:
  - "AI adds a 'copy' button for a password, token, or MFA code, putting the secret on the shared system clipboard where any other app can read it (and clipboard history/cross-device sync retains it)."
  - "AI displays credentials or sensitive financial/health data on a screen without setting FLAG_SECURE (Android), so the OS captures it in the app-switcher snapshot and screenshots/recordings capture it."
  - "AI doesn't obscure sensitive iOS screens on backgrounding, so the app-switcher thumbnail shows the sensitive content."
  - "AI leaves secrets on the clipboard indefinitely instead of clearing/expiring them or marking them sensitive (android:isSensitive / iOS UIPasteboard expiration) where supported."
  - "AI auto-copies OTP/2FA codes to the clipboard for convenience, exposing them app-wide."
falsePositiveGuardrails:
  - "Do not flag copying of non-sensitive data (a shareable link, public text) — the concern is secrets/high-value personal data on the shared clipboard. Establish the data's sensitivity."
  - "Clipboard use that marks the content sensitive and/or clears/expires it (Android sensitive-content flag, iOS pasteboard expiration) materially reduces exposure — factor it in."
  - "Sensitive screens protected with FLAG_SECURE / backgrounding-snapshot obfuscation are correctly hardened — do not flag them; confirm the protection is applied to the sensitive views specifically."
  - "This is a deep-mode, defense-in-depth pass — rank clear secret-to-clipboard and credential-screen-capture exposures above lower-value data."
---

## Root Cause Explanation

Two OS-level conveniences quietly move sensitive data outside the app's control. The
**clipboard** is *shared*: anything copied to the system pasteboard is readable by
every other app on the device, and modern clipboard history and cross-device sync
persist and propagate it. So a "copy password / copy token / copy OTP" affordance —
added purely for user convenience — broadcasts the secret; iOS 14's clipboard-access
notifications famously exposed how many apps were reading the shared pasteboard. The
**screen** is also captured beyond the user's obvious intent: when an app backgrounds,
the OS snapshots its current view for the app switcher (persisted briefly to disk), and
users or other apps can screenshot or screen-record. A screen showing credentials or
high-value data thus leaks through the app-switcher thumbnail and through
screenshots/recordings.

Neither is a code-injection bug; both are **data-exposure side channels** that require
deliberate mitigation. The controls: don't place secrets (passwords, tokens, MFA codes,
card numbers, keys) on the shared clipboard — or if a copy affordance is required, mark
the content sensitive and clear/expire it; and protect sensitive screens from capture
with `FLAG_SECURE` (Android) and by obscuring the view on backgrounding (iOS),
discouraging screenshots for high-value apps.

## Vulnerable Patterns

```dart
// Secret to the shared clipboard — readable by any app
Clipboard.setData(ClipboardData(text: authToken));        // password / token / OTP
```

```kotlin
// Sensitive screen not protected from capture (Android)
// (no window.setFlags(FLAG_SECURE, FLAG_SECURE)) → app-switcher snapshot + screenshots leak it
setContentView(passwordScreen)
```

Correct: keep secrets off the shared clipboard; protect sensitive screens.

```kotlin
window.setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE)    // no capture/snapshot
// iOS: overlay/blur the sensitive view in sceneWillResignActive
```

## Data Flow Tracing Guide

1. Find clipboard writes (Clipboard/UIPasteboard/ClipboardManager) and check whether
   the copied value is sensitive (password/token/OTP/card/key); check for
   sensitive-marking/clearing.
2. Identify screens displaying credentials or high-value sensitive data.
3. Check Android sensitive screens for FLAG_SECURE and iOS for backgrounding-snapshot
   obfuscation.
4. Check for auto-copy of OTP/secrets and clipboard lifetime.
5. Rank secret-to-shared-clipboard and credential-screen-capture as the primary
   exposures.

## Evidence Checklist

- [ ] The clipboard write and the sensitivity of the copied value, quoted.
- [ ] Sensitive screens and their capture protection (FLAG_SECURE / snapshot
      obfuscation) status.
- [ ] Any sensitive-marking / clearing of clipboard content.

## Attack Scenario Template

> [Another app reads the shared clipboard after the user copies a secret / an
> attacker with the device or a screen-recording obtains the app-switcher snapshot or
> a screenshot of the sensitive screen]. Because [file:line] [copies the token/OTP to
> the shared clipboard / does not set FLAG_SECURE on the credential screen], the
> [secret / sensitive data] is exposed, resulting in [credential/data leakage].

## Graph Mapping Instructions

- Ensure a `component:ui_data_exposure` node with an `exposes` edge to
  `component:secrets` for secret-clipboard / credential-screen findings.
- Note the side-channel (shared clipboard / OS snapshot) in `reasoning`.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:ui_data_exposure`.
