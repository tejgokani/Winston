---
id: technology.android.exported_components
title: "Android: Exported Components & Intents"
category: technology
vulnerabilityClass: broken_access_control
appliesToStack: android
requiresAnyTag: ["android"]
deepOnly: false
reviewPass: 1
owaspRefs:
  - "OWASP MASVS-PLATFORM"
  - "A01:2021 Broken Access Control"
cweRefs:
  - "CWE-926"
  - "CWE-927"
  - "CWE-200"
realWorldReferences:
  - title: "OWASP MASTG — testing for exported components / IPC and improper platform usage"
    url: "https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/"
    type: security_blog
  - title: "Android — exported activities/services/receivers/providers and permission enforcement"
    url: "https://developer.android.com/guide/topics/manifest/activity-element#exported"
    type: vendor_security_advisory
  - title: "Exported ContentProvider / Activity leading to data theft or privileged action from a malicious app"
    url: "https://hackerone.com/reports/328486"
    type: bug_bounty_disclosure
quickModeSummary: >
  Exported components (activities, services, broadcast receivers, content
  providers with android:exported=true, or an intent-filter which implies
  exported) can be invoked by ANY other app on the device. Review the manifest and
  component code: flag exported components that perform sensitive actions or
  return sensitive data without a permission/signature check — a malicious app can
  call them (start a privileged activity, bind a service, send a broadcast, query/
  update a content provider) to steal data or trigger actions. Also flag content
  providers exported without granular permissions (SQL-injectable or path-
  traversable query surfaces), implicit intents carrying sensitive data (any app
  can intercept), and PendingIntents that are mutable/underspecified (intent
  redirection). Keep components not-exported unless required; when exported,
  enforce a signature-level permission and validate all incoming Intent data.
fileSelectionHint:
  roles: ["config", "controller", "service", "provider", "receiver"]
  matchImports: ["android", "android.content", "androidx"]
  matchAuthMapTags: ["android"]
  maxFiles: 12
  priorityOrder: ["config", "provider", "service", "controller"]
severityHeuristics:
  critical:
    - "An exported ContentProvider (or a component performing sensitive data access/action) is reachable by any app with no permission/signature check, so a malicious installed app steals data or triggers a privileged action; or the provider's query/openFile is SQL-injectable / path-traversable from a caller"
  high:
    - "An exported activity/service/receiver performs a sensitive operation (auth, data export, privileged action) without a permission or caller-verification check, invocable by any app"
    - "A mutable/underspecified PendingIntent is handed to another app, enabling intent redirection to hijack the app's identity/permissions"
  medium:
    - "Sensitive data is sent via an implicit Intent (any app can receive it), or an exported component validates some but not all incoming Intent extras/URIs before acting on them"
    - "A component is exported unnecessarily (no intent-filter need) though its current actions are low-impact"
  low:
    - "Components are not exported unless required, and exported ones enforce a signature-level permission and validate incoming Intent data — the target state; confirm the permission and validation before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:ipc_surface"
  relatedNodeIds: ["component:authorization", "component:data_store"]
graphEdgeMapping:
  - relation: protects
    from: "component:authorization"
    to: "component:ipc_surface"
  - relation: exposes
    from: "component:ipc_surface"
    to: "component:data_store"
commonAiCodingMistakes:
  - "AI exports a ContentProvider (or leaves it exported by default on older targetSdk) without granular read/write permissions, so any app can query/update it — data theft or a SQL-injection/path-traversal surface reachable cross-app."
  - "AI adds an intent-filter to an activity/service (which implicitly exports it) that performs a sensitive action, without a permission check, letting a malicious app invoke it."
  - "AI sends sensitive data via an implicit Intent (no explicit target), so any app registered for that action can intercept it."
  - "AI creates a mutable PendingIntent (or without FLAG_IMMUTABLE) and gives it to another component/app, enabling intent redirection to act with the app's permissions."
  - "AI trusts Intent extras/URIs from an exported component without validation, so a caller controls file paths, SQL, or action selection."
  - "AI exports a debug/test component that exposes internal functionality."
falsePositiveGuardrails:
  - "Do not flag components that are not exported (android:exported=false, no intent-filter) — they aren't reachable cross-app. Confirm the effective exported state (note the targetSdk default change)."
  - "Exported components that enforce a signature-level permission (only apps signed by the same key can call) and validate incoming Intent data are correctly protected — confirm the permission's protectionLevel."
  - "Components that must be exported for legitimate cross-app use (a share target, a launcher activity) and only perform non-sensitive actions with validated input are fine — severity scales with what the caller can reach."
  - "Immutable, explicit PendingIntents are correct — only mutable/implicit ones are the redirection finding."
---

## Root Cause Explanation

Android apps are built from components — activities, services, broadcast
receivers, content providers — and the manifest decides which are **exported**,
i.e. callable by *other apps on the device*. Any exported component (explicitly,
or implicitly because it declares an intent-filter) is an IPC entry point reachable
by a malicious app the user also installed. If that component performs a sensitive
action or returns sensitive data without checking the caller's permission, the
malicious app simply invokes it: start a privileged activity, bind a service, send
a crafted broadcast, or query/update a content provider to exfiltrate data. Content
providers are especially sharp because their `query`/`openFile` surfaces can be
SQL-injectable or path-traversable from an untrusted caller.

Two related mechanics: **implicit intents** carrying sensitive data can be received
by any app registered for the action, and **mutable/underspecified PendingIntents**
handed to other apps enable intent redirection, letting the recipient act with your
app's identity and permissions. The controls: keep components **not exported**
unless genuinely needed; when exported, enforce a **signature-level permission** (so
only your own signed apps can call) or verify the caller; validate every incoming
Intent extra/URI as untrusted; use explicit intents for sensitive data; and make
PendingIntents immutable and explicit.

## Vulnerable Patterns

```xml
<!-- Exported provider, no permission → any app can query -->
<provider android:name=".DataProvider" android:authorities="com.app.data"
          android:exported="true" />
<!-- Intent-filter implicitly exports a sensitive activity, no permission -->
<activity android:name=".AdminActivity"><intent-filter>...</intent-filter></activity>
```

```kotlin
// Provider query trusting caller-supplied selection → SQL injection
db.query("data", null, selection, selectionArgs, null, null, null)  // selection from caller
// Mutable PendingIntent → redirection
PendingIntent.getActivity(ctx, 0, intent, 0)                        // not FLAG_IMMUTABLE
```

Correct: not exported / signature permission + validated input + immutable
PendingIntent.

```xml
<provider android:name=".DataProvider" android:authorities="com.app.data"
          android:exported="false" />
```

## Data Flow Tracing Guide

1. In the manifest, list every component and its effective exported state
   (explicit, or implicit via intent-filter; account for the targetSdk default).
2. For each exported component, check for a permission (and its protectionLevel —
   signature is strongest) or caller verification.
3. In exported component code, trace incoming Intent extras/URIs into sinks
   (SQL, file paths, action selection) and check validation.
4. Find implicit intents carrying sensitive data and mutable/implicit
   PendingIntents.
5. Rank by what a malicious app can reach (sensitive data/action highest).

## Evidence Checklist

- [ ] The component's exported state and any permission, quoted from the manifest.
- [ ] The sensitive action/data it exposes and the caller-input sinks.
- [ ] The permission protectionLevel or caller check (or absence).
- [ ] PendingIntent mutability/explicitness where relevant.

## Attack Scenario Template

> A malicious app the user installed [queries the exported provider / starts the
> exported activity / sends a broadcast]. Because [file:line] exports the component
> with no [signature permission / caller check] and [does not validate the incoming
> Intent], the malicious app [steals the data / triggers the privileged action /
> injects SQL/paths], resulting in [data theft / unauthorized action].

## Graph Mapping Instructions

- Ensure a `component:ipc_surface` node protected by `component:authorization`,
  with an `exposes` edge to `component:data_store` for data-leaking providers.
- Note the cross-app-reachable rationale in `reasoning`.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:ipc_surface`.
