---
id: ai_security.file_uploads
title: Unrestricted File Upload
category: ai_security
vulnerabilityClass: unrestricted_file_upload
appliesToStack: technology-agnostic
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A04:2021 Insecure Design"
  - "A05:2021 Security Misconfiguration"
cweRefs:
  - "CWE-434"
  - "CWE-22"
  - "CWE-79"
  - "CWE-284"
realWorldReferences:
  - title: "Reddit disclosed on HackerOne: Unrestricted File Upload"
    url: "https://hackerone.com/reports/1606957"
    type: bug_bounty_disclosure
  - title: "My $20,000 S3 bug that leaked everyone's attachments (S3 bucket misconfig of pre-signed URLs) — Bug Bounty Reports Explained"
    url: "https://www.bugbountyexplained.com/my-20000-s3-bug-that-leaked-everyones-attachments-s3-bucket-misconfig-of-pre-signed-urls/"
    type: bug_bounty_disclosure
  - title: "User Data from the Asana S3 Bucket can be leaked via Presigned URL and OSINT — Bugcrowd disclosure"
    url: "https://bugcrowd.com/disclosures/5399313d-b86d-4965-9c32-dbf77660d4ea/user-data-from-the-asana-s3-bucket-can-be-leaked-via-presigned-url-and-osint"
    type: bug_bounty_disclosure
  - title: "Bypassing and Exploiting Bucket Upload Policies and Signed URLs — Detectify Labs"
    url: "https://labs.detectify.com/writeups/bypassing-and-exploiting-bucket-upload-policies-and-signed-urls/"
    type: security_blog
  - title: "Cloud Misconfig Exposes 3TB of Sensitive Airport Data in Amazon S3 Bucket: 'Lives at Stake' — Dark Reading"
    url: "https://www.darkreading.com/application-security/cloud-misconfig-exposes-3tb-sensitive-airport-data-amazon-s3-bucket"
    type: incident_postmortem
  - title: "Supabase Docs — Storage Access Control"
    url: "https://supabase.com/docs/guides/storage/security/access-control"
    type: vendor_security_advisory
  - title: "Cloudflare R2 Docs — Public buckets"
    url: "https://developers.cloudflare.com/r2/buckets/public-buckets/"
    type: vendor_security_advisory
quickModeSummary: >
  Check every file-upload path (multer/formidable/UploadThing/direct-to-S3
  or R2/Supabase Storage): is file type and size validated server-side (not
  just a frontend `accept` attribute)? Is the stored filename/key derived
  from user input without sanitization (path traversal)? Is the destination
  bucket/object publicly readable by default? Is the content-type served in
  a way that lets an uploaded HTML/SVG file execute as script (stored XSS)?
  If presigned URLs are used, is the key path and content-type constrained
  server-side, or can the client pick an arbitrary key/overwrite target?
fileSelectionHint:
  roles: ["route_handler", "api_route", "storage_client", "middleware"]
  matchImports:
    - "multer"
    - "formidable"
    - "busboy"
    - "uploadthing"
    - "@aws-sdk/client-s3"
    - "@aws-sdk/s3-request-presigner"
    - "@supabase/storage-js"
    - "@supabase/supabase-js"
    - "aws-sdk"
    - "cloudflare:r2"
  matchAuthMapTags: ["upload", "storage"]
  maxFiles: 8
  priorityOrder: ["route_handler", "api_route", "storage_client"]
severityHeuristics:
  critical:
    - "Uploaded file is stored with its original extension and served from the same origin/domain with no content-type restriction, allowing an uploaded .html/.svg/.js file to execute as script in a victim's browser (stored XSS) or, on a misconfigured server, as executable code (RCE)."
    - "Storage bucket/object is publicly writable, or a presigned/signed upload URL is scoped so broadly (wildcard key prefix, no content-length/content-type condition) that a client can overwrite arbitrary existing objects, not just create new ones."
    - "User-controlled filename or path segment is used to build the storage key/filesystem path with no sanitization, allowing path traversal (`../../etc/passwd`-style) to overwrite files outside the intended upload directory."
  high:
    - "File type is validated only by client-side `accept` attribute or only by trusting the client-supplied `Content-Type`/MIME field, with no server-side magic-byte or extension allowlist check."
    - "No file size limit enforced server-side, enabling storage exhaustion / denial-of-service via repeated large uploads."
    - "Storage bucket/object defaults to public-read with no evidence the app deliberately intends public content (e.g. user avatars mixed with private documents in the same public bucket)."
  medium:
    - "Presigned upload URL has an unnecessarily long expiry or is not scoped to a single exact key, widening the window/blast radius for URL leakage or reuse."
    - "Uploaded files are deduplicated or served by a predictable/sequential key (e.g. incrementing id or original filename) enabling enumeration of other users' uploads even if the bucket itself is not fully public."
  low:
    - "Missing explicit `Content-Disposition: attachment` on download responses for user-generated file types where inline rendering isn't required (defense-in-depth only, not exploitable alone if content-type sniffing protection is already correct elsewhere)."
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:file_upload"
  relatedNodeIds: ["component:storage", "component:api_security"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:file_upload"
    to: "component:storage"
  - relation: protects
    from: "component:file_upload"
    to: "component:api_security"
commonAiCodingMistakes:
  - "AI scaffolds a multer/formidable upload route with a client-side `accept=\"image/*\"` attribute on the `<input>` and treats that as sufficient validation, never adding a server-side MIME/magic-byte or extension allowlist check on the handler itself."
  - "AI wires an S3/R2 bucket or Supabase Storage bucket to 'public' during scaffolding (because it's the fastest way to get an `<img src>` working in a demo) and that setting survives into the reviewed/production codebase unexamined."
  - "AI builds the storage key or filesystem destination path by directly interpolating `req.file.originalname` or a user-supplied filename field, without stripping path separators or generating a server-side random/UUID key — creating a path-traversal primitive."
  - "AI implements a presigned-URL upload flow but has the client tell the server what key to sign (rather than the server generating the key), so the 'presigned URL is scoped narrowly' security property is undermined at the point the URL is requested, not just at upload time."
  - "AI serves uploaded files directly from the same origin as the main app (e.g. `/uploads/:filename`) without setting `Content-Type: application/octet-stream` or `Content-Disposition: attachment` for non-media types, so a maliciously uploaded `.html` or `.svg` renders and executes in-browser."
  - "AI copies a working upload handler for one file type (e.g. avatars) to a second feature (e.g. document attachments) but drops the size/type validation in the copy because it wasn't factored into a shared, reusable validator."
falsePositiveGuardrails:
  - "Do not flag a public storage bucket automatically — first determine whether the bucket is *intended* to be public (e.g. a CDN-fronted asset bucket for logos/avatars with no sensitive content). The finding is that a bucket is public *and* contains or could contain sensitive/user-private files, or that public-read is the default for a bucket whose purpose hasn't been established."
  - "Do not flag frameworks/services that already enforce server-side validation internally (e.g. UploadThing's configured `fileTypes`/`maxFileSize` on the router, or Supabase Storage's bucket-level `allowed_mime_types`/`file_size_limit` config) as 'missing validation' just because you don't see a manual check in the route handler — verify the library/service config first before concluding validation is absent."
  - "A presigned URL granting write access to a single, server-generated, non-guessable key with a short expiry (minutes) is the correct pattern, not a vulnerability — only flag presigned-URL usage when the key is client-controlled, the expiry is excessive, or the signed policy lacks content-type/content-length conditions."
  - "Do not flag storage of executable-looking file extensions if the application explicitly requires them for its function (e.g. a code-snippet-sharing tool) and demonstrably serves them with `Content-Type: text/plain` / `Content-Disposition: attachment` rather than letting the browser render them — check the serving path, not just the upload path, before concluding XSS is reachable."
---

## Root Cause Explanation

Unrestricted file upload is really three separable trust-boundary failures that
tend to get bundled into one feature, which is exactly why AI-assisted
scaffolding gets it wrong piecemeal — each sub-problem looks "done" once the
happy path (a well-behaved image uploads and displays) works:

1. **Input validation happens on the wrong side of the trust boundary.**
   Frontend `accept="image/*"` and a client-checked file size are UX hints,
   not security controls — both are trivially bypassed by calling the API
   directly. The handler that actually writes the file must independently
   validate type (ideally by magic bytes/content-sniffing, not just the
   client-supplied `Content-Type` header, which is attacker-controlled) and
   size.
2. **The storage destination trusts user input for naming/placement.**
   Filenames and paths derived from user-controlled strings (original
   filename, a "folder" query param) without sanitization let an attacker
   traverse outside the intended directory or predict/collide with another
   user's object key. The fix (server-generated random/UUID keys, an
   allowlisted extension, no path separators from user input) is cheap but
   frequently skipped because it isn't visible in a manual smoke test.
3. **Storage defaults are optimized for "get the demo working," not for
   least privilege.** Public-read buckets, public presigned GET URLs, and
   permissive presigned PUT policies all make the "upload an image, show it
   immediately" flow trivial to build — which is precisely why they're the
   default reached for during scaffolding, and precisely why they need a
   second look before shipping anything that isn't purely public content.
4. **Serving is a second, separate trust boundary from storing.** Even a
   correctly validated, non-traversable, privately-stored file becomes a
   stored-XSS vector if it's later served with a content-type that lets a
   browser render attacker-controlled HTML/SVG/JS as active content from the
   app's own origin. This step is easy to miss because it lives in a
   different code path (the download/serve route) than the upload route
   that got all the review attention.

## Vulnerable Patterns

Look for shapes like these (illustrative, not exhaustive — reason about
equivalents in the actual stack you're reviewing, don't string-match):

```js
// No server-side type/size validation — trusts the client's Content-Type
const upload = multer({ dest: 'uploads/' })
app.post('/upload', upload.single('file'), (req, res) => {
  fs.renameSync(req.file.path, `uploads/${req.file.originalname}`) // path traversal + no validation
})

// Client-controlled key handed to a presigned PUT — server just signs whatever it's asked to
const url = await getSignedUrl(s3, new PutObjectCommand({
  Bucket: 'user-uploads',
  Key: req.body.key, // attacker can set Key: 'other-users/victim/avatar.png'
}))

// Bucket created/configured with public-read, uploaded files served from same origin
// with no content-type hardening: an uploaded profile.svg containing
// <script>fetch('/api/session').then(...)</script> executes when viewed.
```

```ts
// Supabase Storage: bucket created public without considering what gets stored in it
await supabase.storage.createBucket('documents', { public: true })
```

## Data Flow Tracing Guide

To evaluate this playbook responsibly, trace the following before writing any
Finding:

1. Find every upload entry point (multer/formidable/busboy route handler,
   UploadThing file router, a direct-to-S3/R2/Supabase-Storage presigned-URL
   flow). For each, find where type and size are checked — is the check in
   server-executed code (or verified service/bucket config), or only in
   frontend markup/JS?
2. Follow the destination key/path construction. Does any user-controlled
   value (original filename, a form field, a query param) flow into the
   storage key or filesystem path without going through sanitization or
   being discarded in favor of a server-generated identifier?
3. For cloud storage: what is the bucket's actual access configuration
   (public flag, bucket policy, RLS policy for Supabase)? Don't infer this
   from the SDK call alone — check IaC/config files, bucket creation calls,
   or dashboard-configured settings referenced in the repo/docs if present.
4. For presigned-URL flows: who chooses the key — client or server? What
   conditions are set on the signed policy (content-type, content-length,
   key prefix, expiry)? A presigned PUT with no key constraint is
   equivalent to giving the client write access to the whole bucket
   namespace.
5. Find where uploaded files are later served/downloaded. What
   `Content-Type` and `Content-Disposition` headers does that route set? If
   files are served from the same origin as authenticated pages/session
   cookies, an uploaded HTML/SVG rendered inline is a same-origin XSS
   primitive regardless of how well the upload step itself was validated.

## Evidence Checklist

Before submitting a Finding for this playbook, confirm:

- [ ] At least one concrete code snippet with an exact file + line range is
      attached as evidence — do not paraphrase, quote the actual line(s).
- [ ] If claiming missing server-side validation: cite the exact handler and
      confirm (by reading the code, not assuming) that no magic-byte/MIME
      allowlist or size check runs server-side.
- [ ] If claiming path traversal: cite the exact line where a user-controlled
      value reaches the storage key/filesystem path construction.
- [ ] If claiming a public/overly-permissive bucket or presigned policy:
      cite the exact configuration (bucket creation call, IaC snippet, or
      documented policy) that sets the public/permissive state — do not
      infer publicness from usage alone.
- [ ] If claiming stored-XSS-via-upload: cite both the upload path (showing
      the file type isn't restricted to non-executable content) AND the
      serving path (showing the response content-type/disposition that lets
      it render as active content).
- [ ] Confirmation that the bucket/route in question isn't intentionally
      public content with no sensitive data (checked before concluding
      severity).

A finding without at least one concrete code-snippet evidence entry must not
be submitted.

## Attack Scenario Template

> An attacker uploads [file type/content] to [specific upload endpoint].
> Because [specific code location] does not [missing validation/sanitization
> /access-control step], the file is stored at [predictable/traversed/public
> location], resulting in [concrete impact specific to this repo, e.g.
> "the attacker's uploaded SVG executes in the browser of any user who views
> the profile page, exfiltrating their session cookie" or "the attacker
> overwrites another user's `avatar.png` object via an unscoped presigned
> PUT, defacing their profile"].

Fill every bracket concretely from evidence gathered in this repo. If a
bracket can't be filled from real evidence, the scenario is speculative and
severity must be capped at `medium`, with a note that exploitability is
unconfirmed.

## Graph Mapping Instructions

- Always ensure a `component:file_upload` node exists (create it on the
  first upload-related finding in a scan) with a `depends_on` edge to
  `component:storage`.
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type
  `vulnerability`, with a `causes` edge from `component:file_upload` (or a
  more specific root-cause component, e.g. `component:storage` if the root
  cause is bucket configuration rather than the upload handler itself) to
  the finding node.
- If a finding enables reaching a specific downstream component (e.g. a
  stored-XSS finding that can reach `component:session_management` via
  cookie theft, or a path-traversal finding that can reach
  `component:filesystem`), add an `enables` edge from the finding node to
  that component's node id.
- Root cause vs. symptom: if a bucket-configuration finding (e.g. public
  bucket) is the underlying cause of a separate finding (e.g. a specific
  private document being publicly readable), say so explicitly in the
  finding's `reasoning` field so the graph mapper wires a `causes` edge
  between the two finding nodes rather than treating them as unrelated.
