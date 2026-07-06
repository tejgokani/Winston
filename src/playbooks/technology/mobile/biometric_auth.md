---
id: technology.mobile.biometric_auth
title: "Mobile: Biometric & Local Authentication"
category: technology
vulnerabilityClass: broken_authentication
appliesToStack: mobile apps using biometric / local device authentication
requiresAnyTag: ["android", "ios", "flutter", "expo"]
deepOnly: false
reviewPass: 2
owaspRefs:
  - "OWASP MASVS-AUTH"
  - "A07:2021 Identification and Authentication Failures"
cweRefs:
  - "CWE-287"
  - "CWE-603"
  - "CWE-522"
realWorldReferences:
  - title: "OWASP MASTG — testing biometric/local authentication (event-bound vs. result-bound)"
    url: "https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/"
    type: security_blog
  - title: "Android — BiometricPrompt with CryptoObject binding auth to a Keystore key (not a boolean)"
    url: "https://developer.android.com/training/sign-in/biometric-auth"
    type: vendor_security_advisory
  - title: "iOS — LocalAuthentication vs. Keychain access control (kSecAccessControlBiometryCurrentSet) and the 'evaluatePolicy returns true' bypass"
    url: "https://developer.apple.com/documentation/localauthentication"
    type: vendor_security_advisory
quickModeSummary: >
  Biometric/local auth is only as strong as what it gates. The classic bug is
  "event-bound" auth: the app calls BiometricPrompt / LAContext.evaluatePolicy, gets
  a boolean success, and then just proceeds — an attacker on a rooted/jailbroken
  device (or with a Frida hook / patched binary) forces that boolean true and
  bypasses it, because nothing cryptographic depended on the biometric. The secure
  pattern is "result-bound": the biometric unlocks a Keystore/Keychain key (Android
  CryptoObject-bound key, iOS Keychain item with biometric access control) that is
  actually required to decrypt the session/secret — so faking the result yields
  nothing usable. Flag biometric checks that gate only a boolean/navigation, secrets
  retrievable without the biometric-bound key, biometric used as the SOLE factor for
  sensitive server actions (it authenticates the device holder, not the server
  session), and fallbacks that weaken it.
fileSelectionHint:
  roles: ["auth", "service", "controller", "storage"]
  matchImports: ["BiometricPrompt", "LocalAuthentication", "androidx.biometric", "local_auth", "expo-local-authentication"]
  matchAuthMapTags: ["android", "ios", "flutter"]
  maxFiles: 10
  priorityOrder: ["auth", "storage", "service", "controller"]
severityHeuristics:
  critical:
    - "Biometric auth gates access to sensitive data/actions purely by an event/boolean result (evaluatePolicy/BiometricPrompt success → proceed) with no cryptographic binding, so it is bypassable on a rooted/jailbroken/instrumented device (Frida hook, patched return) — the local auth provides no real protection"
  high:
    - "Secrets/session material the biometric is supposed to protect are retrievable WITHOUT the biometric-bound key (stored separately, or the Keychain/Keystore item isn't bound to biometric access control), so bypassing the prompt still yields the data"
    - "Biometric is used as the sole authenticator for a sensitive SERVER-side action without a server-validated session/step-up, treating device-holder verification as server authorization"
  medium:
    - "Biometric is result-bound but the fallback (device passcode / knowledge factor) or re-enrollment handling weakens it (e.g. not invalidated on biometric enrollment change), or CryptoObject/access-control is configured loosely"
    - "The biometric-bound key doesn't require user presence per operation where it should"
  low:
    - "Biometric unlocks a Keystore/Keychain-bound key genuinely required to access the protected secret, invalidated on enrollment change, with server actions still gated by a validated session — the target state; confirm the cryptographic binding before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:local_auth"
  relatedNodeIds: ["component:authentication", "component:secrets"]
graphEdgeMapping:
  - relation: protects
    from: "component:local_auth"
    to: "component:secrets"
  - relation: depends_on
    from: "component:local_auth"
    to: "component:cryptography"
commonAiCodingMistakes:
  - "AI writes `if (await auth.authenticate()) { showSecret() }` — event-bound biometric — so the secret is already available and only a boolean gate stands in the way, trivially bypassed on a rooted/jailbroken device or with a Frida hook."
  - "AI stores the session token/secret in normal storage and 'protects' it with a biometric prompt that doesn't cryptographically gate it — bypass the prompt and read the token directly."
  - "AI uses Android BiometricPrompt WITHOUT a CryptoObject (so no Keystore key is unlocked), or iOS LAContext.evaluatePolicy without tying the result to a biometric-access-controlled Keychain item."
  - "AI treats a successful biometric as server authorization for a sensitive action, instead of proving a server-validated session/step-up — biometric verifies the person holding the device, not the server session."
  - "AI doesn't invalidate the biometric-bound key on enrollment change, so an attacker who enrolls their own fingerprint/face can unlock it."
  - "AI adds a weak fallback that undermines the biometric requirement."
falsePositiveGuardrails:
  - "Do not flag biometric auth that is result-bound: a BiometricPrompt CryptoObject (or iOS Keychain item with kSecAccessControlBiometryCurrentSet) unlocks a Keystore/Keychain key genuinely required to decrypt the protected secret. That is the correct, bypass-resistant pattern — confirm the cryptographic binding."
  - "Biometric as a convenience factor on top of a server-validated session (not the sole server authorizer) is correct — the concern is biometric-as-server-authorization or biometric gating nothing cryptographic."
  - "A Keychain/Keystore key invalidated on biometric enrollment change is correctly hardened — factor it in."
  - "Local device auth is inherently bypassable on a fully compromised device; the standard is that a bypass yields NOTHING usable (no accessible secret). Rate by whether the protected data is cryptographically bound, not by whether the prompt can be skipped."
---

## Root Cause Explanation

Biometric and local authentication verify the person physically holding the device —
useful, but frequently implemented in a way that provides no real security because
it's **event-bound**: the app asks the OS "did biometric auth succeed?", receives a
boolean, and proceeds. On a rooted/jailbroken device, or with a dynamic-instrumentation
tool (Frida) or a patched binary, that boolean is forced to `true` and the check
evaporates — and crucially, the protected data was sitting there accessible the whole
time; the biometric gated only a branch. The secure pattern is **result-bound**: the
biometric unlocks a hardware-backed key (Android `BiometricPrompt` with a
`CryptoObject`-bound Keystore key; iOS a Keychain item with biometric access control)
that is genuinely *required* to decrypt the session token or secret. Now faking the
prompt result yields nothing usable, because the key never released.

Two further errors: treating biometric as **server authorization** (it verifies the
device holder, not your server session — sensitive server actions still need a
server-validated session or step-up), and failing to invalidate the biometric-bound
key on **enrollment change** (so an attacker who adds their own fingerprint/face can
unlock it). The rule: bind the protected secret cryptographically to the biometric,
keep server authorization server-side, and invalidate on enrollment change.

## Vulnerable Patterns

```dart
// Event-bound: boolean gate, secret already accessible → bypassable
if (await localAuth.authenticate(localizedReason: 'Unlock')) {
  showToken(await storage.read('token'));      // token was readable regardless
}
```

```kotlin
// Android BiometricPrompt with no CryptoObject → nothing cryptographic gated
biometricPrompt.authenticate(promptInfo)       // success is just a boolean
```

Correct: result-bound — biometric unlocks a key required to decrypt the secret.

```kotlin
// key generated with setUserAuthenticationRequired(true); cipher via CryptoObject
biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
// only after biometric does `cipher` decrypt the stored token
```

## Data Flow Tracing Guide

1. Find biometric/local-auth calls (BiometricPrompt, LAContext.evaluatePolicy,
   local_auth, expo-local-authentication).
2. Determine binding: does success merely gate a boolean/navigation (event-bound), or
   unlock a Keystore/Keychain key required to access the secret (result-bound)?
3. Check whether the protected secret is retrievable without the biometric-bound key.
4. Check whether biometric is used as server authorization vs. a convenience factor on
   a server-validated session.
5. Check enrollment-change invalidation and fallback strength.

## Evidence Checklist

- [ ] The biometric call and what it gates (boolean vs. crypto key), quoted.
- [ ] Whether the protected secret is bound to the biometric key or retrievable
      without it.
- [ ] Whether biometric is treated as server authorization.
- [ ] Enrollment-change invalidation.

## Attack Scenario Template

> An attacker with a rooted/jailbroken device (or a Frida hook) forces the biometric
> result to success. Because [file:line] is event-bound — the [token/secret] is
> accessible without any biometric-bound key — the bypass grants access to
> [the protected data / the sensitive action], resulting in [account/data compromise].

## Graph Mapping Instructions

- Ensure a `component:local_auth` node with a `protects` edge to
  `component:secrets` and a `depends_on` edge to `component:cryptography`.
- Event-bound findings note the bypassability rationale in `reasoning`.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:local_auth`.
