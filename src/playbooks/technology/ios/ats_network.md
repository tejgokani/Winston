---
id: technology.ios.ats_network
title: "iOS: App Transport Security & TLS"
category: technology
vulnerabilityClass: insecure_communication
appliesToStack: ios
requiresAnyTag: ["ios"]
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
  - title: "Apple — App Transport Security (ATS) and the NSAppTransportSecurity exceptions"
    url: "https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity"
    type: vendor_security_advisory
  - title: "OWASP MASTG — iOS network communication testing (ATS, TLS validation, pinning)"
    url: "https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/"
    type: security_blog
  - title: "Disabled TLS validation in iOS apps (URLSession delegate accepting any cert) enabling MITM"
    url: "https://cwe.mitre.org/data/definitions/295.html"
    type: security_blog
quickModeSummary: >
  iOS enforces HTTPS by default via App Transport Security (ATS) — the insecurity
  comes from apps weakening it or overriding TLS validation. Flag: ATS globally
  disabled (NSAllowsArbitraryLoads=true) or broad per-domain exceptions permitting
  HTTP / weak TLS, especially without a documented justification; URLSession
  delegates that accept any server trust (implementing urlSession(_:didReceive
  challenge:) to call completionHandler(.useCredential, URLCredential(trust:)) for
  any cert, or returning success in evaluateServerTrust) — i.e. custom code that
  defeats certificate/hostname validation; and, for high-value apps, absent
  certificate/public-key pinning where the threat model warrants it. Keep ATS on,
  never bypass server-trust evaluation, and pin for sensitive apps.
fileSelectionHint:
  roles: ["config", "service", "network", "controller"]
  matchImports: ["Foundation", "URLSession", "Security", "Alamofire"]
  matchAuthMapTags: ["ios"]
  maxFiles: 10
  priorityOrder: ["network", "service", "config"]
severityHeuristics:
  critical:
    - "A URLSession/Alamofire delegate defeats TLS validation — accepting any server trust / any certificate / any hostname — so a network MITM intercepts and modifies all traffic including credentials"
  high:
    - "ATS is globally disabled (NSAllowsArbitraryLoads=true) or has broad exceptions permitting HTTP for domains carrying sensitive data, exposing that traffic to network attackers"
    - "Sensitive data is sent to endpoints reachable over HTTP due to ATS exceptions"
  medium:
    - "Narrow ATS exceptions permit cleartext/weak TLS for specific non-sensitive domains without justification, or a high-value app lacks certificate/public-key pinning where warranted"
    - "A debug-only ATS/trust bypass risks shipping to release"
  low:
    - "ATS enabled with no (or narrow, justified, non-sensitive) exceptions, intact server-trust evaluation, and pinning where appropriate — the target state; confirm no trust bypass before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:network_transport"
  relatedNodeIds: ["component:secrets", "component:external_system"]
graphEdgeMapping:
  - relation: protects
    from: "component:network_transport"
    to: "component:secrets"
commonAiCodingMistakes:
  - "AI implements `urlSession(_:didReceive:completionHandler:)` to call `completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))` unconditionally — accepting any certificate — usually to make a self-signed dev cert work, disabling MITM protection app-wide."
  - "AI sets `NSAllowsArbitraryLoads = true` in Info.plist to 'make networking work', disabling ATS globally and permitting HTTP everywhere."
  - "AI adds broad per-domain ATS exceptions (NSExceptionAllowsInsecureHTTPLoads) for domains that carry sensitive data."
  - "AI uses Alamofire `ServerTrustManager`/evaluators configured to disable evaluation, or a custom evaluator that always succeeds."
  - "AI sends sensitive data to an HTTP endpoint enabled by an ATS exception."
  - "AI leaves a debug trust-bypass that ships to release."
falsePositiveGuardrails:
  - "Do not flag apps using default ATS (enabled) with standard URLSession and no trust-bypass delegate — that is correct and MITM-resistant. Only a trust-defeating delegate, ATS disablement, or HTTP exceptions are findings."
  - "Absence of pinning is not automatically a finding — pinning is warranted for high-value apps; for ordinary apps intact ATS + system TLS validation is acceptable. Scope by data sensitivity."
  - "Narrow, justified ATS exceptions for a specific non-sensitive domain (e.g. a legacy media host, documented) are lower risk — confirm no sensitive data and a real justification."
  - "Correct pinning implementations (comparing against a pinned cert/public key) are the target for sensitive apps — do not flag a working pinning implementation."
  - "A debug-only bypass excluded from release is acceptable — confirm it can't ship."
---

## Root Cause Explanation

iOS ships secure-by-default networking: **App Transport Security** requires HTTPS
with modern TLS unless the app explicitly opts out. So, unlike some platforms, the
insecurity here is almost always something the app *adds*: disabling ATS, carving
broad HTTP exceptions, or — most damaging — overriding TLS validation in a
URLSession/Alamofire delegate. The trust-bypass pattern is the critical one: a
delegate that accepts *any* server trust (calling `completionHandler(.useCredential,
URLCredential(trust:))` for whatever certificate is presented, or a custom evaluator
that always succeeds) makes HTTPS cosmetic — a man-in-the-middle on public Wi-Fi or a
rogue access point presents any certificate and the app accepts it, exposing
credentials and all other traffic. As on Android, these bypasses usually enter to
silence a self-signed-cert error in development and then ship.

The controls: leave **ATS enabled** with no (or narrow, justified, non-sensitive)
exceptions; **never** override server-trust evaluation to accept arbitrary
certificates/hostnames; and for high-value apps add **certificate/public-key
pinning** appropriate to the threat model. Ensure any debug bypass is excluded from
release builds.

## Vulnerable Patterns

```swift
// TLS validation defeated — MITM accepted
func urlSession(_ s: URLSession, didReceive c: URLAuthenticationChallenge,
                completionHandler h: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
  h(.useCredential, URLCredential(trust: c.protectionSpace.serverTrust!))   // any cert
}
```

```xml
<!-- ATS disabled globally -->
<key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict>
```

Correct: default ATS, no trust bypass, pinning for sensitive apps.

## Data Flow Tracing Guide

1. Inspect Info.plist NSAppTransportSecurity: global disablement or per-domain HTTP
   exceptions, and whether sensitive-data domains are affected.
2. Search URLSession/Alamofire delegates for server-trust handling that accepts
   arbitrary certs/hostnames or always-succeeds evaluators.
3. Identify sensitive data flows and confirm they stay on validated TLS.
4. For high-value apps, check for pinning appropriate to the threat model.
5. Confirm debug bypasses are excluded from release.

## Evidence Checklist

- [ ] Any trust-bypass delegate/evaluator, quoted.
- [ ] ATS configuration and exceptions.
- [ ] Sensitive data flows and their transport.
- [ ] Pinning presence/absence relative to sensitivity.

## Attack Scenario Template

> An attacker on the same network MITMs the app. Because [file:line] [accepts any
> server trust in the URLSession delegate / disables ATS / permits HTTP for a
> sensitive domain], the app accepts the attacker's certificate (or sends cleartext),
> so the attacker reads and modifies [credentials / API traffic], resulting in
> [account compromise / data theft / tampering].

## Graph Mapping Instructions

- Ensure a `component:network_transport` node with a `protects` edge to
  `component:secrets`.
- Trust-bypass findings note the MITM-accepts-any-cert rationale in `reasoning`.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:network_transport`.
