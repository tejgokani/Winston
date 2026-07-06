---
id: technology.docker.container_hardening
title: Container Hardening (Docker)
category: technology
vulnerabilityClass: insecure_container_configuration
appliesToStack: docker
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A05:2021 Security Misconfiguration"
  - "A08:2021 Software and Data Integrity Failures"
cweRefs:
  - "CWE-250"
  - "CWE-798"
  - "CWE-1104"
realWorldReferences:
  - title: "Codecov — Post-Mortem / Root Cause Analysis (April 2021): GCS key extracted from a Docker image layer"
    url: "https://about.codecov.io/apr-2021-post-mortem/"
    type: incident_postmortem
  - title: "Docker — Building best practices (official docs): USER directive, secrets, and build-time hygiene"
    url: "https://docs.docker.com/build/building/best-practices/"
    type: security_blog
  - title: "OWASP Docker Security Cheat Sheet"
    url: "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html"
    type: security_blog
  - title: "CIS Docker Benchmark"
    url: "https://www.cisecurity.org/benchmark/docker"
    type: vendor_security_advisory
quickModeSummary: >
  Check the Dockerfile for three recurring gaps: (1) no USER directive before
  the final CMD/ENTRYPOINT, so the container process runs as root by default;
  (2) secrets passed via ENV, ARG, or COPY-ed .env files instead of runtime
  injection (secret material becomes recoverable from any image layer via
  `docker history`/`docker save`, even if a later layer deletes the file);
  (3) an unpinned or `:latest` base image (`FROM node:latest`,
  `FROM node` with no tag), which makes builds non-reproducible and silently
  pulls in whatever CVEs exist in the base image at build time.
fileSelectionHint:
  roles: ["infra", "build_config", "deployment"]
  matchImports: ["Dockerfile", "docker-compose.yml", "docker-compose.yaml", ".dockerignore"]
  matchAuthMapTags: ["docker", "container"]
  maxFiles: 8
  priorityOrder: ["build_config", "infra", "deployment"]
severityHeuristics:
  critical:
    - "A real secret (API key, DB credential, private key) is present in an ENV, ARG default value, or COPY-ed file in any layer of the Dockerfile, and the image is pushed to a registry (public or private) reachable by more principals than the app that needs the secret at runtime."
  high:
    - "No USER directive is present before CMD/ENTRYPOINT, so the container's main process runs as root (PID 1 as uid 0), and the image is deployed to a multi-tenant or externally-reachable environment (any container escape or RCE in the app becomes host/root-adjacent)."
    - "ARG is used to pass a secret at build time (`ARG API_KEY`) even if not also set via ENV — build args are stored in the image manifest/history in plaintext and recoverable via `docker history`."
  medium:
    - "Base image is unpinned (`FROM node:latest`, `FROM node`, no digest) in a Dockerfile that builds a production/deployed image, making builds non-reproducible and exposing the app to whatever CVEs exist in the base image at whatever time it happens to be pulled."
    - "A secret was written into an intermediate build stage in a multi-stage build and the file is deleted in a later `RUN rm` — the delete only removes it from the final filesystem view, not from the underlying layer, so it is still recoverable."
  low:
    - "Base image is pinned to a version tag (e.g. `node:20.11.1-alpine`) but not to a content digest (`@sha256:...`), leaving a small window where a tag could be re-pushed by whoever controls the registry namespace."
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:container_build"
  relatedNodeIds: ["component:secrets", "component:deployment_pipeline"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:deployment_pipeline"
    to: "component:container_build"
  - relation: protects
    from: "component:container_build"
    to: "component:runtime_isolation"
commonAiCodingMistakes:
  - "AI scaffolds a Dockerfile from a tutorial or `docker init` template that never includes a USER directive, because the tutorial optimizes for 'it runs' rather than 'it's isolated' — the omission is invisible in local testing since everything works identically as root or non-root until something goes wrong."
  - "AI wires environment variables into the Dockerfile with `ENV API_KEY=${API_KEY}` or `ARG` to 'pass config into the build' because that pattern works for non-secret build-time config (like `NODE_ENV`), and the AI generalizes it to secrets without recognizing the two have very different security properties."
  - "AI (or a scaffolding tool) generates a Dockerfile with `COPY . .` before a `.dockerignore` exists, which pulls in a local `.env` file wholesale into the image — this is the containerized equivalent of committing `.env` to git, but is easy to miss because the file isn't visible in the final `docker run` unless someone thinks to run `docker history` or `docker save | tar -xO`."
  - "AI writes `FROM node:latest` (or `FROM python`, `FROM ubuntu`) when scaffolding a new service because it's the shortest, most 'obviously correct' base image reference in every quick-start guide, and never gets revisited once the project moves past prototyping."
  - "AI 'fixes' a leaked secret by adding a `RUN rm .env` step later in the same Dockerfile stage, believing this removes the secret from the image — it only removes it from the final container filesystem view; the layer containing the original `COPY .env .` (or the `ENV`/`ARG` instruction itself) still contains the plaintext value and is fully recoverable."
falsePositiveGuardrails:
  - "Do not flag a missing USER directive in a Dockerfile intended purely for local development/CI (e.g. named `Dockerfile.dev`, referenced only from a `docker-compose.override.yml`, or explicitly gated to non-production) with the same severity as a production image — note the distinction, but still recommend the fix since dev images are often promoted to prod by accident."
  - "Do not flag ENV vars that hold non-secret configuration (PORT, NODE_ENV, LOG_LEVEL, feature flags) as a secrets-in-layers issue — confirm the value is actually credential-shaped (API key, token, password, private key, connection string with embedded credentials) before citing this as a finding."
  - "Do not flag an unpinned base image as critical/high in isolation — pair it with a check of whether the project has any image-scanning/CI gate (Dependabot, Renovate, Trivy, Snyk in the pipeline) that would catch drift; if such a gate exists, cap severity at medium and note the compensating control."
  - "If secrets are injected via `docker run -e`, `--env-file` at deploy time, Docker/Kubernetes secrets mounts, or a build-time-only BuildKit `--secret` flag (which is NOT persisted to image layers, unlike ARG/ENV), do not flag as secrets-in-layers — verify the actual mechanism before concluding the secret is baked in; BuildKit `--secret` is the correct pattern and should not be penalized."
  - "A base image pinned to a major/minor version tag without a full digest (e.g. `node:20-alpine`) is a low-severity finding, not critical — do not conflate it with a fully unpinned `:latest` reference, which is a materially different (much larger, unbounded) risk window."
---

## Root Cause Explanation

Docker container security failures in AI-scaffolded code cluster around three
root causes, all stemming from the same underlying pattern: the Dockerfile is
optimized for "it builds and runs" rather than "it runs with the isolation
and secret-handling properties production requires."

1. **Missing privilege drop (no `USER` directive).** If a Dockerfile never
   sets `USER`, the container's main process runs as root (UID 0) by
   default — not because anyone chose that, but because it's what happens
   when nothing overrides it. This is invisible during development: the app
   behaves identically whether it's root or not, right up until a
   vulnerability in the app itself (RCE, path traversal, arbitrary file
   write) gets amplified into full control of the container's root
   filesystem, arbitrary binary installation, or — if other isolation layers
   are also weak (privileged mode, mounted Docker socket, kernel
   vulnerability) — a path toward host compromise.
2. **Secrets baked into image layers.** Docker images are a stack of
   immutable layers. Anything written in an earlier layer — a `COPY .env .`,
   an `ENV API_KEY=sk-...`, an `ARG` default or build-time value — persists
   in that layer forever, even if a later layer deletes the file or
   overwrites the variable. The image's layer history (`docker history`,
   or simply unpacking the image tarball with `docker save`) fully recovers
   it. This is functionally identical to committing a secret to git history:
   deleting it in the latest commit doesn't remove it from the repo.
   Multi-stage builds only help if the secret-containing stage is never
   copied into the final stage — the secret is still permanently embedded in
   the intermediate stage's cached layers within the build cache/registry
   unless that stage's layers themselves are never pushed.
3. **Outdated/unpinned base images.** `FROM node:latest` (or any tag-less
   `FROM`) means the base image resolved at build time is whatever the
   upstream maintainer most recently pushed to that tag — different on every
   rebuild, not reviewed, and not guaranteed to match what was tested. This
   breaks reproducibility and silently imports whatever OS/runtime CVEs
   exist in that image at pull time, with no signal to the team that
   anything changed.

## Vulnerable Patterns

Look for shapes like these (illustrative, not exhaustive — reason about
equivalents in the actual Dockerfile/compose setup you're reviewing, don't
string-match):

```dockerfile
# 1. No USER directive — process runs as root by default
FROM node:20-alpine
WORKDIR /app
COPY . .
RUN npm ci
CMD ["node", "server.js"]
# <-- no `USER node` before CMD; PID 1 is root

# 2. Secret baked into a layer via ENV/ARG, or a raw .env COPY
ARG DATABASE_URL
ENV DATABASE_URL=$DATABASE_URL   # embedded in image manifest/history

COPY .env .env                    # if .dockerignore doesn't exclude it,
                                   # this ships the real .env into the image

# "Fixing" it like this does NOT remove it from the layer history:
RUN rm .env

# 3. Unpinned / rolling base image
FROM node:latest
FROM python
FROM ubuntu
```

```yaml
# docker-compose.yml equivalent of the same secrets mistake
services:
  app:
    build: .
    environment:
      - STRIPE_SECRET_KEY=sk_live_xxxxxxxxxxxxxxxx   # hardcoded, not ${VAR}
```

## Data Flow Tracing Guide

To evaluate this playbook responsibly, trace the following before writing any
Finding:

1. Open every `Dockerfile*` in the repo. For each one that builds an image
   intended to run in a real deployment (not a throwaway CI test image),
   check: is there a `USER` instruction before the final `CMD`/`ENTRYPOINT`?
   If yes, confirm the named user is actually non-root (not `USER root`, not
   a user created with UID 0).
2. For every `ENV`, `ARG`, and `COPY`/`ADD` instruction, ask: does the value
   or source file look credential-shaped (API key, token, password,
   connection string with embedded credentials, private key)? If a `.env`
   file (or similar) is copied, check the accompanying `.dockerignore` — is
   it actually excluded, or does `COPY . .` silently include it?
3. If a secret-shaped value appears in an early stage of a multi-stage build
   and a later `RUN rm`/`RUN unset` appears to "clean it up," treat that as
   confirmation the layer-persistence issue applies — the deletion doesn't
   undo the earlier layer.
4. Check the `FROM` line(s) of every Dockerfile: is the base image pinned to
   a specific version (and ideally a digest), or is it `latest`/tag-less/a
   rolling tag (`edge`, `nightly`, `stable` without a version)?
5. Cross-check how secrets actually reach the running container in this
   repo — look for `docker run -e`, `--env-file`, `docker-compose.yml`
   `environment:`/`env_file:` sourcing from a gitignored file, Kubernetes
   `Secret` mounts, or BuildKit `--secret`/`RUN --mount=type=secret`. Any of
   these are the correct pattern and should not be flagged; only flag when
   the secret's value is demonstrably embedded in a built image layer.

## Evidence Checklist

Before submitting a Finding for this playbook, confirm:

- [ ] At least one concrete code snippet with an exact file + line range
      (Dockerfile instruction, compose service block) is attached as
      evidence — do not paraphrase, quote the actual line(s).
- [ ] If claiming a missing-`USER` issue: confirm no `USER` directive exists
      anywhere in the effective build (including any base image the repo
      controls — if the base image itself sets a non-root `USER` and this
      Dockerfile never overrides it back to root, that's a mitigating
      factor, not a finding).
- [ ] If claiming secrets-in-layers: the exact instruction (`ENV`, `ARG`,
      `COPY`) is cited, and the value is confirmed credential-shaped (not a
      generic config value like `NODE_ENV` or `PORT`).
- [ ] If claiming an unpinned base image: the exact `FROM` line is cited,
      and — if a CI/CD scanning gate compensates — that is noted alongside
      the finding rather than omitted.
- [ ] For any secrets-in-layers finding, confirm whether the image is (or is
      likely to be) pushed to a registry any principal beyond the deploying
      service could reach — a secret that never leaves a fully local,
      never-pushed build has a materially different exploitability profile.

A finding without at least one concrete code-snippet evidence entry must not
be submitted.

## Attack Scenario Template

> An attacker gains [read access to the image / RCE in the running
> container] via [specific vector: pull access to the registry storing the
> image at `<path>`; a vulnerability in the app itself reachable at
> `<endpoint>`]. Because [specific Dockerfile line] does not [drop privileges
> / avoid baking in the secret / pin the base image], the attacker is able to
> [recover `<credential>` via `docker history`/`docker save` / act as root
> inside the container and pivot to `<specific resource>` / rely on
> whatever CVEs exist in the unpinned base image at pull time], resulting in
> [concrete impact specific to this repo — e.g. "the extracted database
> credential grants read/write to the production Postgres instance
> referenced in `<file>`," mirroring how the Codecov 2021 breach began with a
> GCS key extracted from a Docker image layer and escalated into a
> months-long supply chain compromise of the Bash Uploader]."

Fill every bracket concretely from evidence gathered in this repo. If a
bracket can't be filled from real evidence, the scenario is speculative and
severity must be capped at `medium`, with a note that exploitability is
unconfirmed.

## Graph Mapping Instructions

- Always ensure a `component:container_build` node exists (create it on the
  first Docker-related finding in a scan) with a `depends_on` edge from
  `component:deployment_pipeline`.
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type
  `vulnerability`, with a `causes` edge from `component:container_build` (or
  a more specific root-cause component, e.g. `component:secrets` if the
  root cause is a secret baked into a layer) to the finding node.
- If a secrets-in-layers finding involves a credential that grants access to
  another modeled component (a database, a cloud provider account, a
  third-party API), add an `enables` edge from the finding node to that
  component's node id — this is what turns an isolated "secret in an image"
  finding into a traceable blast-radius chain in the graph.
- Root cause vs. symptom: if a missing-`USER` finding and a secrets-in-layers
  finding co-occur in the same image, note in the finding's `reasoning`
  field whether privilege escalation from root-in-container would let an
  attacker read out other secrets present in the container's runtime
  environment (not just the build-time layer) — that relationship should be
  wired as a `causes` edge between the two finding nodes rather than left as
  two unrelated findings.
