---
id: technology.android.network_security
title: "Android: Network Security & TLS"
category: technology
vulnerabilityClass: insecure_communication
appliesToStack: android
requiresAnyTag: ["android"]
deepOnly: false
reviewPass: 2
owaspRefs:
  - "OWASP MASVS-NETWORK"
  - "A02:2021 Cryptographic Failures"
cweRefs:
  - "CWE-319"
  - "CWE-295"
  - "CWE-297"
realWorldReferences:
  - title: "OWASP MASTG — network communication testing (cleartext, TLS validation, pinning)"
    url: "https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/"
    type: security_blog
  - title: "Android — Network Security Configuration and cleartextTrafficPermitted defaults"
    url: "https://developer.android.com/privacy-and-security/security-config"
    type: vendor_security_advisory
  - title: "Disabled TLS validation in mobile apps (accepting all certs / all hostnames) enabling MITM"
    url: "https://cwe.mitre.org/data/definitions/295.html"
    type: security_blog
quickModeSummary: >
  Mobile apps run on hostile networks (public Wi-Fi, cellular MITM), so transport
  security matters. Flag: cleartext HTTP traffic (usesCleartextTraffic=true or a
  network-security-config permitting cleartext) carrying any sensitive data;
  disabled/neutered TLS validation — a custom TrustManager that accepts all
  certificates, a HostnameVerifier returning true, or trusting user-added CAs in
  production (network-security-config trust-anchors including "user"); and, for
  high-value apps, absent certificate/public-key pinning where the threat model
  warrants it. Also flag WebViews/HTTP clients that ignore SSL errors. Use HTTPS
  everywhere, keep TLS validation intact (never a permissive TrustManager/Hostname-
  Verifier), restrict trust anchors to system CAs, and pin for sensitive apps.
fileSelectionHint:
  roles: ["config", "service", "network", "controller"]
  matchImports: ["okhttp3", "javax.net.ssl", "java.net", "android.security", "retrofit2"]
  matchAuthMapTags: ["android"]
  maxFiles: 10
  priorityOrder: ["network", "service", "config"]
severityHeuristics:
  critical:
    - "TLS certificate validation is disabled or neutered — a TrustManager accepting all certs, a HostnameVerifier returning true, or SSL errors overridden — so a network MITM can intercept/modify all traffic (including credentials)"
  high:
    - "Sensitive data (credentials, tokens, PII) is transmitted over cleartext HTTP (usesCleartextTraffic / a config permitting cleartext), readable and modifiable by any network attacker"
    - "Production trusts user-added CAs (network-security-config trust-anchors include 'user'), enabling MITM via a user/attacker-installed certificate"
  medium:
    - "Cleartext is permitted for some domains/subresources, or a high-value app transmits sensitive data over TLS but without certificate/public-key pinning where the threat model warrants it"
    - "TLS is enforced but a debug-only insecure config could ship to production"
  low:
    - "HTTPS everywhere with intact TLS validation, system-CA-only trust, and pinning where appropriate — the target state; confirm no permissive TrustManager/cleartext before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:network_transport"
  relatedNodeIds: ["component:secrets", "component:external_system"]
graphEdgeMapping:
  - relation: protects
    from: "component:network_transport"
    to: "component:secrets"
commonAiCodingMistakes:
  - "AI ships a custom `TrustManager` that accepts all certificates (empty checkServerTrusted) or a `HostnameVerifier` returning true — often added to 'fix' a cert error in dev — disabling TLS validation so any MITM reads/modifies traffic."
  - "AI transmits credentials/PII over HTTP, or sets usesCleartextTraffic=true / a network-security-config permitting cleartext."
  - "AI leaves the network-security-config trusting user-added CAs in production, so an attacker (or malware) that installs a CA can MITM the app."
  - "AI overrides WebView/HTTP-client SSL error handling to proceed, or trusts self-signed certs broadly."
  - "AI handles high-value data (banking, health) with no certificate/public-key pinning where the threat model calls for it."
  - "AI leaves a debug insecure networking config that ships to release."
falsePositiveGuardrails:
  - "Do not flag apps using standard HTTPS with the default (intact) TLS validation — that is correct. Only a permissive TrustManager/HostnameVerifier, cleartext, or user-CA trust is a finding."
  - "Absence of pinning is not automatically a finding — pinning is warranted for high-value/high-threat apps; for ordinary apps, intact system TLS validation is acceptable. Scope by the data's sensitivity."
  - "Cleartext permitted only for a specific non-sensitive local/dev domain (and not in the release config) is lower risk — confirm no sensitive data and no release exposure."
  - "A debug-only insecure config guarded so it cannot ship to release is acceptable — confirm it's excluded from release builds."
---

## Root Cause Explanation

A mobile app's network path runs across untrusted infrastructure — public Wi-Fi,
captive portals, cellular interception — so an on-path attacker is part of the
threat model by default. Two failures hand that attacker the traffic. **Cleartext**:
sending anything sensitive over HTTP (or permitting cleartext in the manifest /
network-security-config) means the attacker reads and rewrites it. **Broken TLS
validation**: the far more common and more damaging bug, where the app *uses* HTTPS
but disables its protection — a `TrustManager` that accepts all certificates, a
`HostnameVerifier` that returns true, overriding SSL errors, or trusting user-added
CAs in production. Each of these makes the padlock cosmetic: a MITM presents any
certificate and the app accepts it, exposing credentials and everything else. These
"fixes" usually enter to silence a certificate error during development and then
ship.

The controls: HTTPS everywhere; **never** replace the default TLS validation with a
permissive TrustManager/HostnameVerifier; restrict trust anchors to **system CAs**
(exclude user-added CAs in production via network-security-config); don't override
SSL errors; and for high-value apps add **certificate/public-key pinning** matched
to the threat model. Keep any insecure debug configuration out of release builds.

## Vulnerable Patterns

```kotlin
// TLS validation disabled — MITM accepted
val tm = object : X509TrustManager {
  override fun checkServerTrusted(c: Array<X509Certificate>, t: String) {}   // accepts all
  override fun checkClientTrusted(c: Array<X509Certificate>, t: String) {}
  override fun getAcceptedIssuers() = arrayOf<X509Certificate>()
}
HttpsURLConnection.setDefaultHostnameVerifier { _, _ -> true }               // any hostname
```

```xml
<!-- Cleartext + user CA trust -->
<application android:usesCleartextTraffic="true">
<network-security-config><base-config><trust-anchors>
  <certificates src="user"/></trust-anchors></base-config></network-security-config>
```

Correct: HTTPS, default validation, system CAs, pinning for sensitive apps.

## Data Flow Tracing Guide

1. Grep for custom `TrustManager`/`HostnameVerifier` and SSL-error overrides;
   flag any that accept all certs/hosts or proceed on error.
2. Check `usesCleartextTraffic` and the network-security-config for cleartext
   permission and trust-anchor sources (flag "user" in production).
3. Identify sensitive data flows and confirm they're over TLS.
4. For high-value apps, check for certificate/public-key pinning appropriate to
   the threat model.
5. Confirm insecure debug configs are excluded from release.

## Evidence Checklist

- [ ] Any permissive TrustManager/HostnameVerifier/SSL-error override, quoted.
- [ ] Cleartext permission and trust-anchor config.
- [ ] Sensitive data transmitted and its transport.
- [ ] Pinning presence/absence relative to the app's sensitivity.

## Attack Scenario Template

> An attacker on the same network (public Wi-Fi / rogue AP) MITMs the app. Because
> [file:line] [accepts all certificates / permits cleartext / trusts user-added
> CAs], the app accepts the attacker's certificate (or sends cleartext), so the
> attacker reads and modifies [credentials / PII / API traffic], resulting in
> [account compromise / data theft / tampering].

## Graph Mapping Instructions

- Ensure a `component:network_transport` node with a `protects` edge to
  `component:secrets`.
- Broken-TLS findings note the MITM-accepts-any-cert rationale in `reasoning`.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:network_transport`.
