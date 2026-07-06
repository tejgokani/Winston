---
id: technology.expo_react_native.mobile_security
title: Expo / React Native Mobile Security
category: technology
vulnerabilityClass: sensitive_data_exposure
appliesToStack: expo
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A02:2021 Cryptographic Failures"
  - "A05:2021 Security Misconfiguration"
  - "A08:2021 Software and Data Integrity Failures"
cweRefs:
  - "CWE-798"
  - "CWE-312"
  - "CWE-922"
  - "CWE-940"
realWorldReferences:
  - title: "Expo Docs — Environment variables (EXPO_PUBLIC_ vars are bundled in plain text, never store secrets there)"
    url: "https://docs.expo.dev/guides/environment-variables/"
    type: vendor_security_advisory
  - title: "Expo Docs — SecureStore (Keychain/Keystore-backed encrypted storage vs. unencrypted AsyncStorage)"
    url: "https://docs.expo.dev/versions/latest/sdk/securestore/"
    type: vendor_security_advisory
  - title: "Expo Docs — EAS Environment variables (build-time secrets are not a substitute for runtime secure storage)"
    url: "https://docs.expo.dev/eas/environment-variables/"
    type: vendor_security_advisory
  - title: "React Native Official Docs — Security (JS bundle extraction/decompilation, deep-link scheme hijacking)"
    url: "https://reactnative.dev/docs/security"
    type: vendor_security_advisory
  - title: "Payatu — How to Reverse Engineer React Native Android Apps (bundle decompilation exposing embedded secrets)"
    url: "https://payatu.com/blog/reverse-engineer-react-native-apps/"
    type: security_blog
quickModeSummary: >
  Check three things: (1) are API keys, backend secrets, or credentials
  embedded directly in client code or in EXPO_PUBLIC_-prefixed environment
  variables — anything shipped in the app bundle is trivially extractable
  by decompiling the APK/IPA, so it must be treated as public; (2) is
  AsyncStorage (unencrypted, plaintext on-device) used to persist auth
  tokens, session data, or PII instead of expo-secure-store/Keychain/
  Keystore; (3) does deep link / universal link handling extract
  parameters (tokens, redirect URLs, user ids, admin flags) and act on
  them without validating the source, re-authenticating, or checking them
  server-side, given that any app can register the same custom URL scheme
  and craft malicious links.
fileSelectionHint:
  roles: ["mobile_app", "deep_link_handler", "storage", "config"]
  matchImports: ["expo", "expo-secure-store", "@react-native-async-storage/async-storage", "expo-linking", "expo-router", "react-native"]
  matchAuthMapTags: ["deep_link", "mobile_storage"]
  maxFiles: 8
  priorityOrder: ["deep_link_handler", "storage", "config", "mobile_app"]
severityHeuristics:
  critical:
    - "A backend/third-party secret with broad privileges (a service-role API key, an unrestricted payment provider secret, a write-capable database key) is embedded in client code or an EXPO_PUBLIC_ variable and shipped in the app binary."
    - "A deep link handler reads a parameter (e.g. token, isAdmin, redirectUrl) directly from the incoming URL and uses it to authenticate the user or grant elevated access without any server-side verification."
  high:
    - "Long-lived auth tokens, refresh tokens, or session credentials are persisted in AsyncStorage (or unencrypted MMKV/plain files) instead of expo-secure-store/Keychain/Keystore."
    - "A restricted/rate-limited API key (e.g. a public-but-scoped analytics or maps key) is bundled without domain/bundle-id restriction configured on the provider side, allowing quota-abuse or impersonation."
  medium:
    - "Deep link parameters are used to navigate/pre-fill UI state without validation, creating a phishing or UI-spoofing vector even though no privileged action is taken directly."
    - "Sensitive but non-credential PII (email, name, partial profile data) is cached in AsyncStorage for offline use without encryption."
  low:
    - "Obfuscation/Hermes bytecode compilation is relied upon as the sole protection for an otherwise properly server-validated flow — note as defense-in-depth gap only, not a standalone vulnerability."
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:mobile_client"
  relatedNodeIds: ["component:secrets", "component:local_storage", "component:deep_linking"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:mobile_client"
    to: "component:secrets"
  - relation: depends_on
    from: "component:mobile_client"
    to: "component:local_storage"
  - relation: protects
    from: "component:authentication"
    to: "component:deep_linking"
commonAiCodingMistakes:
  - "AI defines an API key or backend secret as `EXPO_PUBLIC_API_SECRET` in `.env` because the `EXPO_PUBLIC_` prefix is what makes Expo's env-var system 'just work' in client code, without registering that anything with that prefix is compiled in plaintext into the bundle and is publicly extractable."
  - "AI implements 'remember me' or session persistence by calling `AsyncStorage.setItem('authToken', token)` because that's the first storage API surfaced in React Native tutorials, instead of `expo-secure-store`, even in a codebase that already imports `expo-secure-store` elsewhere for other values."
  - "AI wires an `expo-linking`/`expo-router` deep link handler that reads a query param (e.g. `?token=...` or `?userId=...`) and immediately uses it to set auth state or navigate to a privileged screen, treating the URL as if it came from the app's own trusted backend rather than from anywhere an attacker can construct a link."
  - "AI hardcodes a third-party API key (maps, analytics, payments publishable key) directly as a string literal in a component file 'to get it working', then never migrates it to a restricted/scoped key or backend-proxied call before the review."
  - "AI copies an EAS Build 'secret' environment variable pattern used for build-time values (e.g. `NPM_TOKEN`) and assumes the same secret plumbing protects a runtime API key, missing that EAS secrets only protect the build pipeline — anything actually embedded in the compiled app is still extractable at runtime."
falsePositiveGuardrails:
  - "Do not flag an EXPO_PUBLIC_ variable holding a value that is genuinely meant to be public (a publishable/anon key intended for client use, e.g. Stripe's publishable key or a Supabase anon key with RLS enforced server-side) — confirm the key is not a privileged/service-role credential before flagging."
  - "Do not flag AsyncStorage usage for non-sensitive data (UI preferences, feature-flag cache, onboarding-seen flags, non-PII app state) — the concern is specifically credentials, tokens, and PII."
  - "Before flagging a deep link finding, confirm the handler actually consumes untrusted parameters to make a security-relevant decision (auth, navigation to privileged screens, triggering a state-changing action) — a deep link that only navigates to public, non-sensitive content is not a vulnerability."
  - "If a deep link parameter is used but the destination screen independently re-authenticates/re-authorizes the user server-side before performing any sensitive action, the deep link itself is not the vulnerability — note the finding as low/informational rather than high, since the trust boundary is enforced elsewhere."
  - "Universal Links (iOS) / verified Android App Links restrict which app can register a given domain-backed link, which mitigates (but does not eliminate) scheme-hijacking risk — check whether the app uses a custom scheme (e.g. `myapp://`) vs. a verified associated domain before asserting hijacking is trivially exploitable."
---

## Root Cause Explanation

Mobile apps built with Expo/React Native introduce a trust-boundary assumption that web developers often carry over incorrectly: that "client code" is somehow more private than a browser. It is not — an APK or IPA is just a downloadable archive, and the JavaScript bundle inside it (even Hermes-compiled bytecode) can be extracted and decompiled with widely available tooling (APKTool, jadx, react-native-decompiler). Three failure modes recur:

1. **Everything in the bundle is public.** Any string literal, environment variable resolved at build time (especially `EXPO_PUBLIC_*` vars, which Expo explicitly compiles into the JS bundle in plaintext), or hardcoded key ships to every user's device and can be recovered by decompiling the binary. Developers used to server-side `.env` files where "it's in an environment variable" implies secrecy carry that assumption into client code, where it's false.
2. **On-device storage APIs are not uniformly secure.** `AsyncStorage` is a simple, unencrypted key-value store (backed by plaintext files/SQLite depending on platform) designed for app preferences and cache, not secrets. `expo-secure-store` is a different API that wraps the OS's actual secure storage (iOS Keychain, Android Keystore) with encryption. Because both have a similar `setItem`/`getItem` shape, it's easy for a token to end up in the wrong one — especially when AI-assisted scaffolding picks whichever storage import already exists in a file rather than reasoning about sensitivity.
3. **Deep links are attacker-reachable input, not trusted internal navigation.** A deep link (`myapp://reset?token=...`) can be constructed and delivered by anyone — via a phishing message, a malicious app registering the same custom scheme (a real risk pre-iOS 11 and still possible with poorly configured custom schemes), or a crafted universal link. Any handler that reads a query parameter from that link and treats it as authoritative (an auth token, an admin flag, a redirect target) without independent server-side verification is trusting attacker-controlled input.

## Vulnerable Patterns

Illustrative shapes — reason about equivalents in the actual stack under review, don't string-match:

```js
// 1. Secret shipped into the bundle via EXPO_PUBLIC_ prefix
// .env
EXPO_PUBLIC_STRIPE_SECRET_KEY=sk_live_...     // secret key, not publishable — now in every install

// app code
const res = await fetch('https://api.stripe.com/v1/charges', {
  headers: { Authorization: `Bearer ${process.env.EXPO_PUBLIC_STRIPE_SECRET_KEY}` },
});

// 2. Auth token persisted to unencrypted AsyncStorage
import AsyncStorage from '@react-native-async-storage/async-storage';
await AsyncStorage.setItem('authToken', accessToken); // plaintext on disk, readable via backup/root/jailbreak

// vs. correct:
import * as SecureStore from 'expo-secure-store';
await SecureStore.setItemAsync('authToken', accessToken);

// 3. Deep link handler trusting attacker-controlled parameters
import * as Linking from 'expo-linking';

Linking.addEventListener('url', ({ url }) => {
  const { queryParams } = Linking.parse(url);
  if (queryParams.token) {
    setAuthToken(queryParams.token);     // no verification the token is legitimate/server-issued
    navigate('AdminDashboard');
  }
});
```

## Data Flow Tracing Guide

To evaluate this playbook responsibly, trace the following before writing any Finding:

1. Enumerate every environment variable referenced via `process.env.EXPO_PUBLIC_*` and every `app.config.js`/`app.json` `extra` field exposed to the client. For each, trace where its value comes from (`.env`, EAS environment variable dashboard) and classify it: publishable/scoped-safe vs. a privileged secret. Cite the exact reference site and, if available, the corresponding `.env`/config declaration.
2. For every call to `AsyncStorage.setItem`/`multiSet` (or an unencrypted MMKV instance), identify what's being stored. Trace the variable back to its source — is it a token, session id, or PII field returned from an auth/login call? Cross-reference whether `expo-secure-store` is already used elsewhere in the codebase for equivalent data, which is strong evidence the AsyncStorage usage is an inconsistency rather than an intentional choice.
3. For every deep link entry point (`Linking.addEventListener`, `expo-router`'s file-based dynamic routes reachable via a linking config, `Linking.parse`/`useURL`), trace each extracted parameter to its use: does it flow into an auth-state setter, a privileged navigation target, or an API call made with elevated trust? Note whether the destination re-verifies the parameter server-side before acting.
4. Check the app's linking configuration (`app.json`'s `scheme`, or `associatedDomains`/`intentFilters` in a config plugin) to determine whether the app uses a bare custom scheme (hijackable by any other app registering the same scheme) or verified Universal Links/App Links (domain-verified, harder to hijack) — this affects severity, not whether the finding exists.

## Evidence Checklist

Before submitting a Finding for this playbook, confirm:

- [ ] At least one concrete code snippet with an exact file + line range is attached as evidence — do not paraphrase, quote the actual line(s).
- [ ] If claiming a bundled-secret issue: the exact variable/literal and its reference site are cited, and it is shown to be a privileged credential (not a publishable/scoped key).
- [ ] If claiming an insecure-storage issue: the exact `AsyncStorage` call site is cited along with evidence the value stored is a token/credential/PII (trace to its origin, e.g. a login response).
- [ ] If claiming a deep-link issue: the exact parameter-extraction site AND the exact downstream use (auth decision, privileged navigation, API call) are cited, with confirmation there is no independent server-side re-verification.
- [ ] The app's linking configuration (custom scheme vs. verified Universal/App Links) was checked and is reflected in the assigned severity.

A finding without at least one concrete code-snippet evidence entry must not be submitted.

## Attack Scenario Template

> An attacker [decompiles the app's APK/IPA using standard tooling and extracts a bundled secret / crafts a malicious deep link and delivers it via phishing or a competing app registering the same URL scheme / reads on-device storage on a rooted or jailbroken device]. Because [specific code location] does not [avoid embedding the secret client-side / use expo-secure-store / validate the deep link parameter server-side], the attacker obtains [concrete artifact — e.g. "a live payment-provider secret key" or "another user's session token"], resulting in [concrete impact specific to this repo, e.g. "unauthorized charges against the merchant account" or "full account takeover without needing the victim's password"].

Fill every bracket concretely from evidence gathered in this repo. If a bracket can't be filled from real evidence, the scenario is speculative and severity must be capped at `medium`, with a note that exploitability is unconfirmed.

## Graph Mapping Instructions

- Always ensure a `component:mobile_client` node exists (create it on the first Expo/React Native finding in a scan), with `depends_on` edges to `component:secrets` and `component:local_storage` as relevant findings appear.
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type `vulnerability`, with a `causes` edge from the most specific root-cause component (`component:secrets` for bundled-key issues, `component:local_storage` for insecure-storage issues, `component:deep_linking` for deep-link trust issues) to the finding node.
- If a bundled-secret finding enables reaching a specific external system (a payment provider, a database via a leaked service key), add an `enables` edge from the finding node to that component's node id.
- If a deep-link finding is a downstream consequence of a missing server-side authentication component (e.g. no `component:authentication` re-check exists for the flow), add a `depends_on` edge from `component:deep_linking` to `component:authentication` and note the gap explicitly in the finding's `reasoning` field so the graph mapper can connect it to any related JWT/session findings from other playbooks rather than treating it as isolated.
