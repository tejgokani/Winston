---
id: technology.android.webview
title: "Android: WebView Security"
category: technology
vulnerabilityClass: broken_isolation
appliesToStack: android
requiresAnyTag: ["android"]
deepOnly: false
reviewPass: 2
owaspRefs:
  - "OWASP MASVS-PLATFORM"
  - "A03:2021 Injection"
cweRefs:
  - "CWE-749"
  - "CWE-79"
  - "CWE-939"
realWorldReferences:
  - title: "Android — addJavascriptInterface RCE (CVE-2012-6636) and the JS-to-native bridge risk"
    url: "https://developer.android.com/develop/ui/views/layout/webapps/webview#BindingJavaScript"
    type: vendor_security_advisory
  - title: "OWASP MASTG — WebView testing: JavaScript bridges, file access, mixed content"
    url: "https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0033/"
    type: security_blog
  - title: "WebView file-access + loadUrl(file://) enabling local file theft via loaded web content"
    url: "https://hackerone.com/reports/1332433"
    type: bug_bounty_disclosure
quickModeSummary: >
  A WebView that renders web content next to a JavaScript-to-native bridge is
  Android's version of the Electron isolation problem. Flag: addJavascriptInterface
  exposing app/native methods to loaded web content (pre-API-17 this was direct
  RCE; still dangerous if any untrusted/remote content loads or an injected script
  runs — the exposed methods become the attacker's API); JavaScript enabled while
  loading remote/untrusted or mixed-content (HTTP) pages; file access enabled
  (setAllowFileAccess / setAllowFileAccessFromFileURLs / setAllowUniversalAccess-
  FromFileURLs) letting loaded content read local files (file:// theft); loading
  URLs built from untrusted input (loading attacker pages into the app's WebView);
  and ignoring TLS errors (onReceivedSslError proceeding). Only expose native
  bridges to trusted local content, disable file access, load over HTTPS, and never
  proceed past SSL errors.
fileSelectionHint:
  roles: ["view", "controller", "service", "config"]
  matchImports: ["android.webkit", "WebView", "WebViewClient", "androidx.webkit"]
  matchAuthMapTags: ["android"]
  maxFiles: 10
  priorityOrder: ["view", "controller", "service"]
severityHeuristics:
  critical:
    - "addJavascriptInterface exposes native/app methods to a WebView that loads remote/untrusted content (or where an XSS in loaded content is possible), so web JavaScript can invoke the exposed native capability — bridge-to-native compromise (RCE-class on affected versions / powerful capability abuse otherwise)"
  high:
    - "File access is enabled (setAllowFileAccessFromFileURLs / setAllowUniversalAccessFromFileURLs) on a WebView that loads untrusted content, enabling theft of local files; or the WebView loads a URL built from untrusted input, loading attacker content into the app context"
    - "SSL errors are ignored (onReceivedSslError -> proceed()), so a MITM can inject content into the WebView"
  medium:
    - "JavaScript is enabled while loading remote/mixed-content pages without a strict need, or the JS bridge is exposed to trusted content but with an overly broad method surface"
    - "The WebView loads HTTP (mixed) content, or navigation isn't restricted to trusted origins"
  low:
    - "A WebView loading only trusted bundled content, with file access disabled, HTTPS-only, no native bridge (or a minimal bridge to trusted content), and SSL errors not overridden — the target state; confirm before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:webview_bridge"
  relatedNodeIds: ["component:remote_code_execution", "component:local_storage"]
graphEdgeMapping:
  - relation: causes
    from: "component:webview_bridge"
    to: "component:remote_code_execution"
commonAiCodingMistakes:
  - "AI uses `addJavascriptInterface` to let the web UI call native methods and loads remote/untrusted content in the same WebView, so any injected or malicious web script invokes the native bridge (historically direct RCE via reflection; still a powerful capability handoff)."
  - "AI enables `setAllowUniversalAccessFromFileURLs`/`setAllowFileAccessFromFileURLs` so loaded content can read arbitrary local files (file:// exfiltration)."
  - "AI builds the WebView URL from an intent extra / deep-link / server value, loading attacker-controlled pages into the app's WebView context."
  - "AI overrides `onReceivedSslError` to call `handler.proceed()`, disabling TLS validation and enabling MITM content injection."
  - "AI enables JavaScript and loads mixed-content (HTTP) pages, allowing injection over the network."
  - "AI exposes a broad native bridge surface to content that could be XSS'd."
falsePositiveGuardrails:
  - "Do not flag a WebView that loads only trusted, bundled local content with no untrusted/remote loading — a native bridge to genuinely trusted first-party content is a normal pattern. Confirm what the WebView loads."
  - "File access disabled (setAllowFileAccessFromFileURLs/UniversalAccess false) and HTTPS-only loading are the correct settings — only enabled file access with untrusted content, or mixed/remote content, is the finding."
  - "A minimal, well-scoped JS bridge (specific safe methods) exposed only to trusted content is acceptable — severity scales with the content's trust and the bridge's power."
  - "WebViews that do NOT override onReceivedSslError (default rejects bad certs) are correct — only proceed()-on-error is the finding."
  - "Cross-reference the general xss playbook for the web content itself; report the WebView-bridge/isolation angle here."
---

## Root Cause Explanation

An Android `WebView` embeds web content inside the app, and — like Electron — the
danger is the bridge between that web content and native capability. `addJavascript
Interface` exposes app methods to page JavaScript; on Android < 4.2 this was direct
remote code execution (via reflection), and even on modern versions it hands loaded
content an API into the app. So a WebView that both exposes a native bridge *and*
loads remote, mixed, or otherwise untrusted content (or content that can be XSS'd)
lets web JavaScript drive native functionality. The other WebView-specific holes
are **file access** (`setAllowFileAccessFromFileURLs`/`setAllowUniversalAccessFrom
FileURLs`) letting loaded content read the device's local files, **loading
untrusted URLs** (building the WebView URL from an intent/deep-link/server value,
so an attacker's page runs in the app context), and **ignoring TLS errors**
(`onReceivedSslError -> proceed()`), which reopens the content to network MITM.

The controls: expose native bridges only to trusted, bundled content; disable file
access; load over HTTPS only and never build the URL from untrusted input; never
proceed past SSL errors; and keep the bridge surface minimal. Treat any remotely-
loaded or user-influenceable content as hostile to the native bridge.

## Vulnerable Patterns

```kotlin
val wv = WebView(this)
wv.settings.javaScriptEnabled = true
wv.addJavascriptInterface(NativeApi(), "Android")            // native bridge...
wv.settings.allowUniversalAccessFromFileURLs = true          // ...+ file access...
wv.loadUrl(intent.getStringExtra("url"))                     // ...+ untrusted URL

override fun onReceivedSslError(v: WebView, h: SslErrorHandler, e: SslError) { h.proceed() } // MITM
```

Correct: trusted local content, no file access, HTTPS, no bridge to untrusted
content.

```kotlin
wv.settings.allowFileAccessFromFileURLs = false
wv.settings.allowUniversalAccessFromFileURLs = false
wv.loadUrl("https://app.example.com/embedded")               // fixed, HTTPS
// no onReceivedSslError override (default rejects bad certs)
```

## Data Flow Tracing Guide

1. Find every WebView and its settings: JavaScript enabled, addJavascriptInterface,
   file-access flags.
2. Determine what it loads: bundled/trusted vs. remote/untrusted vs. a URL from
   untrusted input.
3. If a native bridge is exposed, assess the content's trust and the bridge's
   method surface.
4. Check `onReceivedSslError` for proceed()-on-error and mixed-content loading.
5. Rank: native bridge + untrusted content is critical; file access + untrusted is
   high.

## Evidence Checklist

- [ ] The WebView settings and addJavascriptInterface usage, quoted.
- [ ] What the WebView loads (trust + source of the URL).
- [ ] File-access flags and SSL-error handling.
- [ ] The bridge method surface exposed to loadable content.

## Attack Scenario Template

> An attacker [gets untrusted content loaded into the WebView via the URL-from-input
> / MITMs the HTTP or SSL-error-ignoring load / injects script into remote content].
> Because [file:line] exposes [a native bridge / file access] to that content, the
> web JavaScript [invokes the native method / reads local files], resulting in
> [native capability abuse or RCE / local file theft].

## Graph Mapping Instructions

- Ensure a `component:webview_bridge` node with a `causes` edge to
  `component:remote_code_execution` for bridge findings.
- File-access findings add an `exposes` edge to `component:local_storage`.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:webview_bridge`; cross-link to xss for the content itself.
