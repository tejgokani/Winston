---
id: ai_security.cryptographic_failures
title: Cryptographic Failures
category: ai_security
vulnerabilityClass: cryptographic_failure
appliesToStack: technology-agnostic
deepOnly: false
reviewPass: 2
owaspRefs:
  - "A02:2021 Cryptographic Failures"
cweRefs:
  - "CWE-327"
  - "CWE-328"
  - "CWE-330"
  - "CWE-916"
  - "CWE-759"
realWorldReferences:
  - title: "LinkedIn 2012 breach — 6.5M (later ~117M) password hashes cracked because they were unsalted SHA-1"
    url: "https://www.troyhunt.com/heres-everything-i-know-about-the-linkedin-breach/"
    type: incident_postmortem
  - title: "Adobe 2013 breach — 150M credentials with ECB-mode encryption (not hashing) and reused blocks made passwords recoverable"
    url: "https://nakedsecurity.sophos.com/2013/11/04/anatomy-of-a-password-disaster-adobes-giant-sized-cryptographic-blunder/"
    type: incident_postmortem
  - title: "OWASP — Password Storage Cheat Sheet (argon2id/bcrypt/scrypt, per-password salt, work factors)"
    url: "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"
    type: security_blog
  - title: "CWE-330 — Use of Insufficiently Random Values (Math.random for tokens/session ids)"
    url: "https://cwe.mitre.org/data/definitions/330.html"
    type: security_blog
  - title: "OWASP — Cryptographic Storage Cheat Sheet (AES-GCM, unique IVs/nonces, key management)"
    url: "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"
    type: security_blog
quickModeSummary: >
  Review every use of cryptography, hashing, and randomness. The high-value
  bugs: passwords stored with a fast/general-purpose hash (MD5, SHA-1,
  SHA-256, or any unsalted hash) instead of a password hashing function
  (argon2id, bcrypt, scrypt); security-sensitive tokens (session ids, reset/
  verification tokens, API keys, nonces) generated with a non-cryptographic
  RNG (`Math.random()`, `rand()`, `random.random()`, predictable seeds)
  instead of a CSPRNG; encryption using a broken/ECB mode, a hardcoded or
  reused IV/nonce, or a hardcoded/committed key; weak or absent key
  derivation for keys derived from passwords; and rolling custom crypto
  instead of a vetted library. Also flag secrets compared with a
  non-constant-time equality (timing side channel) and TLS/cert verification
  disabled. The two costliest patterns historically are unsalted fast-hash
  password storage (LinkedIn) and encrypting-instead-of-hashing passwords in
  ECB mode (Adobe).
fileSelectionHint:
  roles: ["auth", "service", "model", "crypto", "util", "config", "middleware"]
  matchImports:
    ["crypto", "bcrypt", "bcryptjs", "argon2", "scrypt", "jsonwebtoken", "hashlib", "passlib", "pycryptodome", "cryptography", "openssl", "node-forge", "crypto-js"]
  matchAuthMapTags: ["auth", "crypto"]
  maxFiles: 10
  priorityOrder: ["auth", "crypto", "service", "util"]
severityHeuristics:
  critical:
    - "Passwords (or password-equivalent secrets) are stored using a fast/general-purpose hash (MD5, SHA-1, SHA-2 family, or any single unsalted hash) or reversible/ECB-mode encryption, rather than a slow password-hashing function (argon2id/bcrypt/scrypt) with a per-password salt"
    - "A cryptographic key, or a secret used to sign tokens/sessions, is hardcoded in source or committed to the repo, so anyone with the code can forge tokens or decrypt data"
  high:
    - "A security-sensitive value (session id, password-reset/verification token, API key, CSRF token, nonce) is generated with a non-cryptographic RNG (Math.random, rand, random.random, time-seeded) making it predictable/guessable"
    - "Symmetric encryption uses a broken mode (ECB) or a static/reused/zero IV or nonce (e.g. the same IV for AES-CBC/GCM across messages), defeating confidentiality/integrity"
  medium:
    - "A key derived from a password/passphrase uses no or a weak KDF (raw hash, low iteration count) instead of PBKDF2/scrypt/argon2 with an adequate work factor, or bcrypt/argon2 work factors are set implausibly low"
    - "A secret/HMAC/token is compared with a non-constant-time equality (== / string compare) enabling a timing side channel, or a deprecated cipher (DES/3DES/RC4) is used"
  low:
    - "Custom/hand-rolled cryptographic construction (bespoke encrypt/MAC scheme) where a vetted primitive exists, or a weak-but-non-security-critical hash used for a genuinely non-security purpose (confirm the purpose before downgrading)"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:cryptography"
  relatedNodeIds: ["component:authentication", "component:secrets_management"]
graphEdgeMapping:
  - relation: protects
    from: "component:cryptography"
    to: "component:authentication"
  - relation: depends_on
    from: "component:cryptography"
    to: "component:secrets_management"
commonAiCodingMistakes:
  - "AI hashes passwords with `crypto.createHash('sha256')` / `hashlib.sha256` / MD5 because those are the hashing functions it reaches for by default, not registering that password storage specifically requires a deliberately-slow salted KDF (argon2id/bcrypt/scrypt) — a fast hash lets an attacker who steals the database crack billions of guesses per second (the LinkedIn failure)."
  - "AI generates a password-reset token, session id, or API key with `Math.random()` / `Math.random().toString(36)` / `random.randint` because they're the obvious 'random' functions, not realizing these are non-cryptographic PRNGs whose output is predictable — the token should come from `crypto.randomBytes`/`secrets.token_urlsafe`/`crypto.randomUUID`."
  - "AI encrypts with AES in ECB mode (the default for some libraries' simple API) or hardcodes/reuses a static IV/nonce, not recognizing that ECB leaks plaintext structure (identical blocks → identical ciphertext, the Adobe failure) and that a reused IV breaks CBC/GCM/CTR security."
  - "AI hardcodes an encryption key or a JWT signing secret directly in the source ('for now') or commits it, so the key ships in the repo/bundle and anyone can forge or decrypt — this compounds with the JWT and secrets-management playbooks."
  - "AI compares an incoming token/HMAC/API key with `===`/`==`/`String.equals`, introducing a timing side channel; secret comparisons must use a constant-time compare (`crypto.timingSafeEqual`, `hmac.compare_digest`)."
  - "AI derives an encryption key from a user password with a single hash (or a low-iteration KDF) instead of a proper password-based KDF with a high work factor, making the derived key brute-forceable."
falsePositiveGuardrails:
  - "Do not flag password storage that uses argon2id, bcrypt, or scrypt with a per-password salt and a reasonable work factor — that is the correct pattern. Confirm the actual function; a call to a `hash`-named helper may wrap bcrypt internally."
  - "A fast hash (SHA-256, etc.) used for a genuinely non-secret purpose — content addressing, cache keys, checksums, ETag generation, deduplication — is correct and not a finding. Establish that the hashed value is security-sensitive (a password, a token) before flagging."
  - "`crypto.randomBytes`, `crypto.randomUUID`, `secrets.token_*`, `SecureRandom`, and `window.crypto.getRandomValues` are CSPRNGs and correct for token/id generation — do not flag these. Math.random used for non-security purposes (UI jitter, sampling, non-security cache-busting) is also fine; confirm the value is security-sensitive."
  - "AES-GCM / AES-CBC with a freshly-generated random IV/nonce per operation (and, for GCM, the auth tag verified) is correct — only ECB, or a static/reused IV, is the finding. Confirm how the IV is produced before flagging."
  - "A key sourced at runtime from an env var / secrets manager (not a literal in source) is not a hardcoded-key finding, even if the variable is named `KEY` — trace the value's origin."
---

## Root Cause Explanation

Cryptographic failures are rarely about a broken algorithm — they're about
using a *correct* primitive for the wrong job, or a broken *mode/parameter*
around a correct primitive. AI-generated code is unusually prone to this
because the wrong choice is almost always the more obvious one. Asked to
"hash the password," a model reaches for `sha256` or `md5` — real hashing
functions, just the wrong *kind* for passwords. Asked for a "random token,"
it reaches for `Math.random()` — a real random function, just not a
cryptographically secure one. The result compiles, passes tests, and looks
completely normal, while being catastrophically weak against an attacker who
obtains the data.

The two most expensive breaches in this class illustrate the two halves.
LinkedIn stored passwords as unsalted SHA-1: a fast, general-purpose hash
with no per-password salt, so once the database leaked, commodity hardware
cracked the bulk of them in short order. The fix is a *deliberately slow*,
*salted* password-hashing function — argon2id, bcrypt, or scrypt — whose
work factor makes mass cracking economically infeasible. Adobe did something
even worse: it *encrypted* passwords (reversibly) in ECB mode with no salt,
so identical passwords produced identical ciphertext blocks and password
hints leaked the rest. Passwords must be hashed, never encrypted.

The randomness half is just as damaging and even easier to miss. Session
ids, password-reset tokens, verification codes, API keys, and nonces derive
their entire security from unpredictability. A non-cryptographic PRNG
(`Math.random`, `rand`, time-seeded generators) produces output an attacker
can predict or brute-force, turning "unguessable token" into "guessable." A
CSPRNG (`crypto.randomBytes`, `secrets`, `getRandomValues`) is the only
acceptable source. The remaining surface — hardcoded keys, ECB mode, reused
IVs, weak KDFs, non-constant-time secret comparison, and hand-rolled crypto
— all share the same shape: a plausible-looking construction that quietly
removes the property the cryptography was supposed to provide.

## Vulnerable Patterns

```js
// Password stored with a fast, unsalted hash — crackable at scale
const hash = crypto.createHash("sha256").update(password).digest("hex");

// Security token from a non-cryptographic PRNG — predictable
const resetToken = Math.random().toString(36).slice(2);

// ECB mode / reused IV — leaks plaintext structure
const cipher = crypto.createCipheriv("aes-256-ecb", key, null);

// Hardcoded key / signing secret
const JWT_SECRET = "supersecret123";

// Timing side channel on a secret compare
if (providedToken === storedToken) { /* ... */ }
```

Correct shapes use a password KDF, a CSPRNG, an authenticated mode with a
fresh IV, sourced keys, and constant-time comparison:

```js
const hash = await argon2.hash(password);                       // or bcrypt/scrypt, salted
const resetToken = crypto.randomBytes(32).toString("hex");      // CSPRNG
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);   // fresh IV, auth tag verified
const key = process.env.ENCRYPTION_KEY;                         // sourced, not literal
crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));         // constant-time
```

## Data Flow Tracing Guide

1. Find every password/credential storage path. Identify the exact function:
   is it a password KDF (argon2/bcrypt/scrypt) with a salt, or a fast hash /
   reversible encryption? Flag the latter.
2. Find every generation of a security-sensitive token/id/nonce/key. Identify
   the RNG: CSPRNG or a predictable PRNG? Confirm the value is
   security-sensitive before flagging.
3. For each encryption call, determine the mode (flag ECB), the IV/nonce
   source (flag static/reused/zero), and whether GCM auth tags are verified.
4. Trace every cryptographic key and signing secret to its origin: env/secrets
   manager (ok) vs. literal-in-source/committed (finding).
5. Find secret/HMAC/token equality checks; flag non-constant-time comparisons.
6. Note any hand-rolled cryptographic construction where a vetted primitive
   exists.

## Evidence Checklist

- [ ] The exact hashing/encryption/RNG call site quoted, with the function/
      mode/RNG named.
- [ ] For password storage: confirmation of KDF vs. fast-hash and salt
      presence.
- [ ] For tokens: the RNG source and why the value is security-sensitive.
- [ ] For encryption: mode, IV/nonce source, and key origin.
- [ ] For hardcoded keys: the literal and what it protects/signs.

A finding without the specific call site and the named weak primitive/mode/
RNG must not be submitted.

## Attack Scenario Template

> An attacker who [obtains the database via another vulnerability / observes
> issued tokens / obtains the source or bundle] exploits [file:line], where
> [passwords are stored as unsalted SHA-x / the reset token comes from
> Math.random / AES-ECB with a static IV is used / the signing key is
> hardcoded]. Because [the fast hash allows billions of guesses/sec / the
> PRNG output is predictable / ECB leaks structure / the key is known],
> the attacker [recovers user passwords at scale / predicts a victim's reset
> token and takes over the account / recovers plaintext / forges valid
> tokens], resulting in [impact].

## Graph Mapping Instructions

- Ensure a `component:cryptography` node exists, with a `protects` edge to
  `component:authentication` for password/token findings.
- Password-storage and token-predictability findings are account-takeover
  class — add an `enables` edge from the finding node to
  `component:authentication` and flag it in `reasoning` so severity
  aggregation weighs them as auth compromises.
- Hardcoded-key findings add an `exposes` edge to
  `component:secrets_management`.
- Each concrete weakness is a `finding:<uuid>` vulnerability node with a
  `causes` edge from `component:cryptography`.
