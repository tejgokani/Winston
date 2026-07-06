---
id: technology.firebase.security_rules
title: "Firebase: Firestore/Realtime Database Security Rules Misconfiguration"
category: technology
vulnerabilityClass: broken_access_control
appliesToStack: firebase
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A01:2021 Broken Access Control"
cweRefs:
  - "CWE-284"
  - "CWE-862"
  - "CWE-863"
realWorldReferences:
  - title: "Misconfigured Firebase Instances Expose 125 Million User Records (SecurityWeek, covering research by mrbruh, xyzeva, logykk)"
    url: "https://www.securityweek.com/misconfigured-firebase-instances-expose-125-million-user-records/"
    type: incident_postmortem
  - title: "The Tea App Data Breach: What Really Happened (Firebase/GCS storage misconfiguration exposing 1.1M+ private messages and 72K+ images)"
    url: "https://sentra.io/blog/how-the-tea-app-got-blindsided-on-data-security"
    type: incident_postmortem
  - title: "Analysing Misconfigured Firebase Apps: A Tale of Unearthing Data Breaches — Project Resonance Wave 10 (RedHunt Labs)"
    url: "https://redhuntlabs.com/blog/analysing-misconfigured-firebase-apps-a-tale-of-unearthing-data-breaches-wave-10/"
    type: research_paper
  - title: "Avoid insecure rules — Firebase Security Rules official documentation"
    url: "https://firebase.google.com/docs/rules/insecure-rules"
    type: vendor_security_advisory
  - title: "Fix insecure rules — Cloud Firestore Security documentation"
    url: "https://firebase.google.com/docs/firestore/security/insecure-rules"
    type: vendor_security_advisory
quickModeSummary: >
  For every Firestore/Realtime Database security rules file: does any rule
  use `allow read, write: if true` (test-mode default left in production)?
  Does a rule check only `if request.auth != null` without also verifying
  the requester owns/is authorized for the specific resource (e.g. missing
  `request.auth.uid == resource.data.ownerId`)? For Realtime Database
  specifically, does a broad rule at a parent path unintentionally grant
  access that a narrower child-path rule cannot revoke (rules cascade
  downward and can only add privileges, never restrict them)? Is a Cloud
  Storage bucket's access control/IAM policy or its own security rules file
  separately reviewed, since Storage misconfiguration is a distinct and
  equally common failure from Firestore/RTDB rules?
fileSelectionHint:
  roles: ["config", "database", "backend"]
  matchImports: ["firebase", "firebase-admin", "firebase/firestore", "firebase/database"]
  matchAuthMapTags: ["firebase"]
  maxFiles: 8
  priorityOrder: ["config", "database"]
severityHeuristics:
  critical:
    - "A deployed rules file (firestore.rules, database.rules.json, or storage.rules) contains `allow read, write: if true` (or the RTDB/Storage equivalent `\".read\": true, \".write\": true`) on any path touching non-public data — this is the exact 'test mode' default that Google's own documentation calls out as never safe in production, and is the root cause of incidents exposing 100M+ records."
    - "No rules file is present in the repository at all / the project appears to still be running Firebase's default test-mode rules (evidenced by absence of a `firestore.rules`/`database.rules.json` deploy step or explicit rules content)."
    - "A Cloud Storage bucket backing user uploads has no rules file or an open ACL, exposing files (images, documents, exported data) via predictable/guessable URLs — mirrors the Tea app breach root cause, which was a Storage misconfiguration distinct from Firestore rules."
  high:
    - "A rule checks only `request.auth != null` (any logged-in user) on a path containing per-user or per-tenant data, without also checking resource ownership (e.g. missing `request.auth.uid == resource.data.uid` or an equivalent tenant/ownership check)."
    - "A Realtime Database rule at a parent path grants broad access (e.g. `.read: true` at `/`) and a developer has added a narrower rule deeper in the tree believing it restricts access — RTDB rules cascade downward and cannot revoke a broader grant from an ancestor path, so the child rule is a no-op."
    - "Rules reference a client-writable field (e.g. a `role` or `isAdmin` field stored on the same document the user can otherwise write) to make an authorization decision, allowing self-escalation."
  medium:
    - "Rules correctly gate reads/writes by `request.auth.uid` but never validate the *shape*/type of written data (no `request.resource.data.keys().hasOnly([...])` or type checks), allowing a legitimate user to write arbitrary extra fields or malformed data into their own documents."
    - "Firebase Admin SDK credentials (a service account JSON key) are found in a location reachable by client-side/bundled code — the Admin SDK bypasses all security rules entirely, analogous to Supabase's service_role key exposure."
  low:
    - "Rules are correctly scoped but lack rate-limiting/validation against write-amplification (e.g. no cap on array/list growth), a defense-in-depth gap rather than an active access-control bypass."
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:firebase_security_rules"
  relatedNodeIds: ["component:authorization", "component:database", "component:backend_as_a_service"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:firebase_security_rules"
    to: "component:authorization"
  - relation: protects
    from: "component:firebase_security_rules"
    to: "component:database"
commonAiCodingMistakes:
  - "AI (or a developer following AI-suggested quick-start steps) leaves the project in Firebase's 'Test mode' — which sets `allow read, write: if true` — because test mode is the fastest path to a working demo, and no automated step in a typical AI-assisted workflow reminds the agent to lock rules down before the code is considered 'done'. Google's own Firebase blog names this pattern directly as the most common source of insecure rules found in code review."
  - "AI writes a rule that checks `if request.auth != null` because that satisfies the immediate prompt ('only logged-in users can access this'), without reasoning about per-resource ownership — functionally the same class of mistake as the Supabase 'checks auth.role() = authenticated instead of auth.uid() = user_id' pattern, just expressed in Firebase's rules DSL."
  - "AI treats Firestore rules and Cloud Storage rules as the same surface and only writes/reviews one of them — e.g. it secures Firestore documents correctly but leaves the Storage bucket (used for file uploads, exports, profile images) on default/open rules, since Storage requires its own separate rules file (`storage.rules`) that isn't always top-of-mind when scaffolding a Firestore-centric app."
  - "AI generates a Firebase Admin SDK service account key usage example (common in Node.js backend scaffolding) and the key file or its contents end up copied into a location that also gets bundled for the client (e.g. a shared `config` module imported by both server and client code), producing a full-bypass credential leak that's easy to introduce and hard to notice via rules review alone since it bypasses rules entirely."
  - "AI writes a Realtime Database rule nested several levels deep intending to restrict access, unaware that RTDB rules cascade and a broader ancestor rule already granted access that the child rule cannot revoke — this produces confident-looking but non-functional restrictions that a naive 'is there a rule here?' check would pass."
falsePositiveGuardrails:
  - "Do not flag `allow read: if true` on data that is genuinely intended to be public (e.g. published blog posts, public product listings) — confirm the collection's business purpose before assuming every open read rule is a vulnerability. The same permissiveness on a `users`, `messages`, or `orders` collection is a different story."
  - "Do not flag Firebase Admin SDK usage as a rules bypass when it is confirmed to run only in a trusted server environment (a Cloud Function, a Node.js backend never bundled for the browser) — trace the actual import/build reachability before concluding the credential is client-exposed, the same way you would for a Supabase service_role key."
  - "A rules file that denies all access by default (`if false`) and relies entirely on the Admin SDK from trusted Cloud Functions is a valid and common architecture, not a vulnerability — do not flag 'overly restrictive' rules as a finding; only flag rules that grant more access than the application's own data-ownership model calls for."
  - "Firebase API keys (the `apiKey` field in client SDK config) are not secrets and are expected to be public — do not flag their presence in client code as a credential leak. The actual security boundary is the rules file, not the API key; only service account JSON keys / Admin SDK credentials constitute a real credential exposure."
  - "For Realtime Database, always check ancestor paths before concluding a child-path rule is protective — a correctly-scoped rule at `/users/$uid` can still be moot if `/` or `/users` grants `.read: true`, since child rules can only add privileges, not subtract them; conversely, don't assume a broad-looking top-level rule is the active one without checking whether it's actually overridden by design at every reachable child path."
---

## Root Cause Explanation

Like Supabase, Firebase (Firestore, Realtime Database, and Cloud Storage) is
a backend-as-a-service model where the client talks directly to the database
over the network, and **security rules are the entire authorization layer**
— there is no server-side route handler quietly enforcing access control
behind the scenes unless the app is explicitly architected that way (e.g.
routing all writes through Cloud Functions with an Admin SDK and denying
direct client writes in rules). If the rules are wrong, the data is exposed
exactly as widely as the rules allow, full stop.

This produces a small number of recurring failure modes, ranked by real-world
frequency:

1. **Test-mode rules shipped to production.** When a Firestore/Realtime
   Database is created, developers choose between "Locked mode" (deny all)
   and "Test mode" (`allow read, write: if true` — open to everyone). Test
   mode is meant to be temporary during early development, but it is
   extremely common for it to survive into production because nothing
   forces a re-visit before deploy. This exact pattern is documented as the
   root cause of one of the largest disclosed cloud-data-exposure incidents
   on record: a 2024 investigation (mrbruh, xyzeva, logykk) found ~900
   misconfigured Firebase-backed sites exposing roughly 125 million user
   records — names, emails, phone numbers, and in some cases plaintext
   passwords — all traceable to the same class of open rules.
2. **Authenticated-but-unrestricted access.** A rule checks
   `request.auth != null` and stops there. This blocks anonymous internet
   traffic but grants every logged-in user full access to every other
   user's data — a narrower but still severe variant of the same underlying
   mistake.
3. **Realtime Database rule cascading confusion.** RTDB rules apply
   top-down: a rule at a parent path grants access that a more restrictive
   rule at a child path *cannot* revoke — child rules can only grant
   *additional* privileges, never subtract from what an ancestor already
   granted. Developers (and AI agents) writing a "tighter" rule deep in the
   tree while a broader rule sits above it produce a rule that looks
   protective but is a functional no-op.
4. **Storage bucket misconfiguration treated as out-of-scope.** Cloud
   Storage has its own separate rules file and access model from
   Firestore/RTDB. The Tea app breach (2025) is a direct example: the app's
   custom API was properly secured, but a Cloud Storage bucket used for
   image/message data was left with excessive access permissions after a
   data migration, exposing over 1.1 million private messages and 72,000
   images — the database rules being "fine" told reviewers nothing about
   the separately-configured storage layer.
5. **Admin SDK credential exposure.** Analogous to a Supabase service_role
   key leak — Admin SDK service account credentials bypass all rules
   entirely, so their exposure to client-reachable code is a full bypass,
   not a rules problem at all.

## Vulnerable Patterns

```
// Firestore — "test mode" default left in production.
// Firebase's own documentation states this must NEVER be used in production.
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true;
    }
  }
}
```

```
// Firestore — authenticated but not authorized: any logged-in user can
// read/write every other user's documents in this collection.
match /users/{userId} {
  allow read, write: if request.auth != null;
  // Should be: if request.auth != null && request.auth.uid == userId;
}
```

```json
// Realtime Database — broad grant at a parent path that a child rule
// cannot override. Rules cascade; child rules can only ADD privileges.
{
  "rules": {
    ".read": true,
    ".write": true,
    "users": {
      "$uid": {
        ".read": "auth != null && auth.uid === $uid"
        // This looks protective but the top-level ".read": true already
        // granted global read access — this child rule changes nothing.
      }
    }
  }
}
```

```js
// Admin SDK / service account credentials reachable from shared code that
// also gets bundled for the client — bypasses all security rules entirely.
import serviceAccount from "../config/firebase-service-account.json";
// If `../config/` is imported by any client-bundled module, this is a
// full-bypass credential leak, not a rules misconfiguration.
```

## Data Flow Tracing Guide

To evaluate this playbook responsibly, trace the following before writing any
Finding:

1. Locate every deployed rules file in the repo: `firestore.rules`,
   `database.rules.json`/RTDB rules, and `storage.rules`. If one of the
   three is missing entirely for a project that clearly uses that product
   (check `firebase.json` for configured targets), treat that as evidence
   the project may still be on Firebase's default test-mode rules — verify
   before concluding, but don't ignore the gap.
2. For each `match` block (Firestore) or path (RTDB), classify the
   condition: `true` (open), `request.auth != null` only (authenticated but
   unscoped), or a genuine ownership/resource check
   (`request.auth.uid == resource.data.ownerId` or equivalent). Cite the
   exact path and condition.
3. For Realtime Database specifically, walk the rules tree top-down from
   `/` and note the first `.read`/`.write` value set at each level — a
   `true` at any ancestor path makes deeper restrictions on that subtree
   ineffective. Do not evaluate a child rule in isolation.
4. Separately review `storage.rules` (or confirm its absence/openness) even
   if Firestore/RTDB rules are correctly configured — this is a distinct
   attack surface with its own rules file, as demonstrated by the Tea app
   breach where the API layer was secure but Storage was not.
5. Grep for Firebase Admin SDK initialization (`firebase-admin`,
   `admin.initializeApp`, service account JSON imports) and trace whether
   the importing module is reachable from any client-bundled entry point.
6. Check whether any rule references a field the same rule (or a sibling
   write rule) allows the client to set — this indicates a
   self-escalation path via client-writable authorization data.

## Evidence Checklist

Before submitting a Finding for this playbook, confirm:

- [ ] The exact rules file + path/match-block + condition is quoted (not
      paraphrased) as evidence.
- [ ] If claiming test-mode/open rules: confirmation of which collection or
      path is affected and whether it contains non-public data.
- [ ] If claiming authenticated-but-unscoped access: the exact rule
      condition is cited, and the specific ownership field it's missing
      (e.g. `ownerId`, `uid`) is identified from the data model.
- [ ] If claiming an RTDB cascading issue: both the ancestor rule and the
      child rule are cited together, showing the ancestor already grants
      the access the child rule appears to restrict.
- [ ] If claiming a Storage misconfiguration: the specific bucket/path
      rule (or its absence) is cited, distinct from any Firestore/RTDB
      finding.
- [ ] If claiming an Admin SDK credential leak: the file/line where the
      credential is referenced, and the import chain showing client-bundle
      reachability.

A finding without at least one concrete rules-file or code-snippet evidence
entry must not be submitted.

## Attack Scenario Template

> An unauthenticated (or any authenticated) attacker calls the Firebase
> client SDK directly against `[collection/path]`, using only the public
> `apiKey` (which is not a secret and requires no special access). Because
> [specific rules file:path] either sets `allow read, write: if true`, or
> checks [insufficient condition] instead of resource ownership, the
> request returns [concrete data — e.g. "every user's document including
> plaintext password field" or "all private messages between all users"]
> with no legitimate access to that data required. This mirrors the pattern
> behind the 125-million-record Firebase exposure documented by security
> researchers in 2024 and the Tea app Storage-bucket breach in 2025.

Fill every bracket concretely from evidence gathered in this repo. If a
bracket can't be filled from real evidence, the scenario is speculative and
severity must be capped at `medium`, with a note that exploitability is
unconfirmed.

## Graph Mapping Instructions

- Always ensure a `component:firebase_security_rules` node exists (create it
  on the first Firebase-rules-related finding in a scan) with a `depends_on`
  edge to `component:authorization`.
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type
  `vulnerability`, with a `causes` edge from `component:firebase_security_rules`
  to the finding node.
- If a finding involves an Admin SDK credential exposed to client-reachable
  code, also add a `causes` edge from `component:secrets` to that finding
  node, and an `enables` edge from the finding node to `component:database`,
  since it represents a full bypass rather than a rules-scoping issue.
- If a finding involves Cloud Storage specifically (distinct from
  Firestore/RTDB), add a `relatedNodeIds` reference to a
  `component:file_storage` node so the graph distinguishes it from
  database-document findings, matching how the Tea app incident involved a
  storage-layer failure independent of the API/database layer.
- Root cause vs. symptom: if a finding is *caused by* another finding already
  identified in this scan (e.g. an RTDB parent-path rule causing a
  child-path rule to be a no-op), say so explicitly in the finding's
  `reasoning` field so the graph mapper can wire a `causes` edge between the
  two finding nodes rather than treating them as unrelated.
