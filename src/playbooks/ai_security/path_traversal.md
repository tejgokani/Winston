---
id: ai_security.path_traversal
title: Path Traversal (General File Access)
category: ai_security
vulnerabilityClass: path_traversal
appliesToStack: technology-agnostic
deepOnly: false
reviewPass: 3
owaspRefs:
  - "A01:2021 Broken Access Control"
cweRefs:
  - "CWE-22"
  - "CWE-23"
  - "CWE-36"
  - "CWE-73"
realWorldReferences:
  - title: "Jenkins CLI Arbitrary File Read via @-file argument expansion (CVE-2024-23897, CVSS 9.8)"
    url: "https://www.jenkins.io/security/advisory/2024-01-24/"
    type: vendor_security_advisory
  - title: "8x8/Jitsi jitsi-call-analytics — Unauthenticated arbitrary file write via path traversal in /api/v1/uploads/analyze (HackerOne)"
    url: "https://www.redpacketsecurity.com/hackerone-bugbounty-disclosure-jitsi-call-analytics-unauthenticated-arbitrary-file-write-via-path-traversal-in-api-v-uploads-analyze-r-skr-der/"
    type: bug_bounty_disclosure
  - title: "U.S. Dept of Defense — Path traversal in downloadForm endpoint via filename parameter (HackerOne #1888808)"
    url: "https://hackerone.com/reports/1888808"
    type: bug_bounty_disclosure
  - title: "Aiven-hosted Grafana 8.x — Zero-day path traversal allows unauthenticated arbitrary local file read (HackerOne)"
    url: "https://hackerone.com/reports/1415820"
    type: bug_bounty_disclosure
  - title: "OWASP — Path Traversal"
    url: "https://owasp.org/www-community/attacks/Path_Traversal"
    type: security_blog
  - title: "CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"
    url: "https://cwe.mitre.org/data/definitions/22.html"
    type: security_blog
quickModeSummary: >
  Find every place a filename/path arrives from a request (query param, body
  field, header, URL segment, form field, config value pulled from user data)
  and is used in a filesystem read, write, delete, list, or serve operation.
  Check whether the resulting path is verified to stay inside an intended
  base directory (resolved/normalized THEN prefix-checked) or merely
  string-blocklisted ("../" stripped once, case-sensitive check, no
  normalization). This is the general file-access case, not upload-specific
  handling (see file_uploads.md for that).
fileSelectionHint:
  roles: ["route_handler", "controller", "file_service", "static_server", "cli_handler", "download_handler", "export_handler", "backup_service", "template_engine"]
  matchImports: ["fs", "path", "os.path", "pathlib", "send_file", "sendFile", "createReadStream", "shutil", "zipfile", "tarfile", "multer", "express.static"]
  matchAuthMapTags: []
  maxFiles: 10
  priorityOrder: ["route_handler", "file_service", "controller", "static_server"]
severityHeuristics:
  critical:
    - "User-controlled path reaches a filesystem write/delete/overwrite operation (arbitrary file write, e.g. via zip/tar extraction, backup restore, template write) with no containment check"
    - "User-controlled path reaches a read of files that plausibly contain credentials/secrets (config files, SSH keys, environment files, cloud metadata paths) with no containment check"
  high:
    - "User-controlled path reaches a filesystem read (arbitrary file read) with containment check absent or bypassable (blocklist-only, no normalization before comparison)"
    - "Archive extraction (zip/tar) writes entries using the archive's own entry names without validating each resolved path stays within the target directory (zip-slip pattern)"
  medium:
    - "Containment check exists but compares the raw (unnormalized) input against a prefix, or normalizes but doesn't resolve symlinks, leaving a narrower bypass"
    - "Path traversal is possible but scoped to a low-sensitivity directory (e.g. a per-user scratch space) with no path to sensitive data"
  low:
    - "Traversal-shaped input is rejected only by a generic input validator upstream (defense-in-depth gap, not directly exploitable in the traced flow)"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:file_access"
  relatedNodeIds: ["component:filesystem", "component:api_security", "component:secrets"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:file_access"
    to: "component:filesystem"
  - relation: protects
    from: "component:file_access"
    to: "component:secrets"
commonAiCodingMistakes:
  - "AI writes `path.join(baseDir, req.query.filename)` and treats `path.join`/`os.path.join` as if it sandboxes the result — in most languages, join happily produces a path outside `baseDir` when the second argument contains `../` sequences (or, in Python/Node, an absolute path silently discards the base entirely)."
  - "AI adds a single `.replace('../', '')` or regex strip as the entire defense, which is trivially bypassed with `..//`, `....//`, URL-encoded (`%2e%2e%2f`), double-encoded, or OS-specific (`..\\`) sequences, or by non-recursive replacement (`....//` becomes `../` after one pass)."
  - "AI validates the path before normalization instead of after — checking `filename.includes('..')` on the raw string, then separately calling `path.resolve`/`path.normalize`, so a payload that doesn't literally contain `..` but normalizes into one (or is checked before a decode step) slips through."
  - "AI implements archive (zip/tar) extraction with the library's default extract-all behavior and doesn't validate each entry's resolved path stays within the target directory before writing it — the classic zip-slip pattern, root cause behind CVE-2024-23897-adjacent and the Jitsi jitsi-call-analytics disclosure above."
  - "AI scaffolds a 'download by filename' or 'export/backup restore' endpoint, correctly sandboxes the read path, then later a 'similar' write/delete endpoint (delete export, overwrite backup) is added by copy-pasting the read endpoint's routing but the containment check doesn't get carried over, or is weaker because writes were treated as lower-risk than reads."
  - "AI trusts a path segment from a URL route param (e.g. `/files/:folder/*`) differently than a query param, sanitizing one but not realizing the other reaches the same filesystem sink."
falsePositiveGuardrails:
  - "Do not flag a filename/path parameter that's only ever used as a lookup key into a database or an allowlist/enum of known-safe values (never concatenated into a filesystem path) — trace to the actual sink before concluding it's a traversal risk."
  - "Do not flag frameworks' built-in static file servers (e.g. `express.static`, Django's `staticfiles`, nginx `alias`) as vulnerable by default — these have traversal protection built in; only flag if the codebase's own custom code additionally manipulates the requested path before/after the framework call."
  - "Confirm the actual sink: `open()`/`fs.readFile()`/`send_file()` on a resolved path is a real sink; a path merely being logged, hashed, or used to build a display string is not."
  - "If a containment check exists, verify whether it resolves/normalizes the path (following `..` and symlinks) BEFORE the prefix comparison — a check performed on the raw string is a real bypassable finding; a check performed after `path.resolve`/`os.path.realpath` and compared with `startsWith(resolvedBase + sep)` is likely sound. Don't flag the latter as a false positive out of pattern-matching against the former's shape."
  - "Server-side path construction entirely from trusted, hardcoded, or server-generated identifiers (e.g. a UUID the server itself generated and stores) is not attacker-controlled input — no finding, even if the code superficially resembles a vulnerable pattern."
---

## Root Cause Explanation

Path traversal happens when a filesystem operation's target path is built,
even partially, from data an attacker can influence, and the code trusts that
the result stays inside whatever directory it "should" be in. Three failure
modes account for almost every real case:

1. **Join is not jail.** `path.join(base, userInput)`, `os.path.join(base,
   userInput)`, and equivalents in every language are string-concatenation
   utilities, not sandboxes. They resolve `..` segments and, in most
   languages, silently discard `base` entirely if `userInput` is an absolute
   path. Code that "looks" like it's constraining the path to `base` isn't,
   unless the *result* is checked afterward.
2. **Blocklists instead of allowlists/containment checks.** Stripping literal
   `../` substrings once, checking `.includes('..')` on the raw string, or
   rejecting a fixed set of "bad" characters all fail against encoding
   variants (`%2e%2e%2f`, double-encoding), OS-specific separators (`..\\`
   on Windows-hosted code, mixed separators), non-greedy replacement
   (`....//` → `../` after one pass of stripping `../`), or null-byte/UTF-8
   overlong tricks depending on runtime. The only reliable check is:
   normalize/resolve the final path, then verify it is a strict descendant of
   the intended base directory.
3. **The seam problem.** As MITRE's own root-cause framing puts it, path
   traversal tends to live at the boundary between the code that receives
   external input (an HTTP handler) and the code that performs the
   filesystem operation (a service/utility function), often written at
   different times. By the time the value reaches `fs.readFile`/`open()`, it
   no longer visually resembles "user input" — it's just `filePath`. This is
   exactly the pattern that produces false confidence in both human- and
   AI-written code: the read/write call looks locally correct because the
   reviewer (or the AI) isn't tracing back far enough to see where the
   variable originated.

This playbook is distinct from `file_uploads.md`: that playbook covers
traversal that arrives specifically through an upload's filename/content-type
handling. This playbook covers every other file-serving, file-reading,
file-writing, file-deleting, or archive-extracting code path — download
endpoints, export/report generators, backup/restore features, template or
plugin loaders, log viewers, static asset servers with custom logic layered
on top, and CLI tools that accept a path argument.

## Vulnerable Patterns

Illustrative shapes, not exhaustive — reason about equivalents in the actual
language/framework under review:

```js
// Node/Express — join() does not constrain the result
app.get('/download', (req, res) => {
  const filePath = path.join(__dirname, 'files', req.query.name);
  res.sendFile(filePath); // ../../etc/passwd traverses right out of 'files'
});
```

```python
# Python — no normalization before use
@app.route('/logs/<path:filename>')
def get_log(filename):
    return send_file(os.path.join(LOG_DIR, filename))  # filename can be ../../../etc/passwd
```

```python
# "Sanitization" that doesn't survive normalization or encoding
if '..' in filename:
    raise ValueError('bad path')
full_path = os.path.join(BASE_DIR, filename)  # ..%2f..%2f still reaches here undecoded, or
                                                # a later decode step reintroduces '..'
```

```js
// zip-slip: archive entry names used as write paths with no containment check
for (const entry of zip.entries()) {
  fs.writeFileSync(path.join(extractDir, entry.fileName), entry.getData());
  // entry.fileName can be "../../../../var/www/html/shell.php"
}
```

The correct shape resolves and *checks containment after resolution*:

```js
const target = path.resolve(baseDir, userInput);
if (!(target === baseDir || target.startsWith(baseDir + path.sep))) {
  throw new Error('path escapes base directory');
}
```

## Data Flow Tracing Guide

1. Enumerate every filesystem sink in the reviewed files: read (`open`,
   `fs.readFile`, `send_file`, `sendFile`, `createReadStream`), write
   (`fs.writeFile`, `open(..., 'w')`), delete (`fs.unlink`, `os.remove`),
   list/stat (`fs.readdir`, `os.listdir`), and archive extraction
   (`zipfile.extractall`, `tar.extractall`, `unzipper`, `adm-zip`).
2. For each sink, trace the path argument backward to its origin. Is any
   segment of it sourced from `req.query`, `req.params`, `req.body`, a
   header, a URL path segment, form data, or an archive entry name? If the
   entire path is server-constructed from hardcoded or server-generated
   values (UUIDs, DB-issued IDs), it is not in scope for this playbook.
3. If attacker-influenced, find where (if anywhere) the path is validated.
   Identify the *order of operations*: is validation performed on the raw
   input before normalization (weak), or on the resolved/normalized path
   compared against the resolved base directory (strong)?
4. For archive extraction specifically: does the extraction loop validate
   each entry's resolved destination path individually, or does it call a
   bulk `extractall`-style method with no per-entry check?
5. Determine the blast radius: what does `baseDir` contain, and what's
   reachable via traversal from it? Reading arbitrary files up to the
   filesystem root (`/etc/passwd`, SSH keys, cloud instance metadata files,
   application config/secrets) is categorically worse than traversal
   confined to a sibling directory with no sensitive contents — cite what's
   actually reachable, don't assume worst-case without checking.
6. For writes: what could an attacker overwrite or create? Writing into a
   web-served directory (RCE via webshell), a cron/systemd unit path, an
   application config file, or an authorized_keys-equivalent file is
   critical; writing into an isolated per-request scratch directory that
   gets discarded is not.

## Evidence Checklist

- [ ] Exact file + line range of the filesystem sink call is cited.
- [ ] Exact file + line range showing the attacker-controlled origin of the
      path value (query param / body field / header / entry name) is cited,
      with the traced connection between origin and sink made explicit if
      they're in different files/functions.
- [ ] The validation/containment logic (if any) is quoted verbatim, and its
      order of operations (validate-then-normalize vs. normalize-then-validate)
      is stated explicitly — do not assert a bypass without showing why the
      specific validation shown fails to catch it.
- [ ] For a claimed bypass of an existing check: a concrete payload string
      that would pass the shown validation and still escape the base
      directory (e.g. `....//....//etc/passwd`, `%2e%2e%2f`, an absolute
      path override) is given.
- [ ] What's reachable at the destination (for reads) or overwritable (for
      writes) is stated concretely, not assumed.

A finding without the sink line, the origin line, and the validation
logic (or explicit absence thereof) quoted must not be submitted.

## Attack Scenario Template

> An attacker sends [request shape] with [parameter] = [traversal payload,
> e.g. `../../../../etc/passwd` or a zip entry named `../../var/www/shell.php`].
> Because [specific code location] performs [describe exact operation:
> join-without-containment-check / blocklist-bypassable-by-X], the resulting
> path resolves to [concrete file/location outside the intended directory],
> and the [read/write/delete] operation at [sink location] executes against
> it, resulting in [concrete impact: disclosure of X credential file / RCE
> via webshell written to Y / overwrite of Z config].

Fill every bracket from evidence gathered in this repo. If the destination
file/impact can't be confirmed concretely (e.g. you don't know what's at the
resolved path in this deployment), cap severity at `medium` and note that
exploitability/impact is unconfirmed.

## Graph Mapping Instructions

- Ensure a `component:file_access` node exists on the first path-traversal
  finding in a scan, with a `depends_on` edge to `component:filesystem`.
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type
  `vulnerability`, with a `causes` edge from `component:file_access` to the
  finding node.
- If the traced sink is a write/extract operation that lands inside a
  web-served or execution path (enabling code execution), add an `enables`
  edge from the finding node to `component:api_security` (or a more specific
  `component:remote_code_execution` node if the graph schema in use supports
  it) — don't understate a write-primitive finding as equivalent in severity
  to a read-only finding.
- If the traced sink reads a file that stores credentials/secrets
  (`.env`, SSH keys, cloud metadata, DB connection strings), add an
  `enables` edge from the finding node to `component:secrets`.
- If a finding is caused by another finding already in this scan (e.g. a
  missing-auth finding is what exposes the vulnerable download endpoint to
  unauthenticated attackers in the first place), state that relationship
  explicitly in the finding's `reasoning` field so the graph mapper can wire
  a `causes` edge between the two finding nodes.
