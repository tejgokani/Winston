---
id: technology.kubernetes.workload_security
title: "Kubernetes: Workload & Manifest Hardening"
category: technology
vulnerabilityClass: security_misconfiguration
appliesToStack: kubernetes
requiresAnyTag: ["kubernetes"]
deepOnly: false
reviewPass: 2
owaspRefs:
  - "A05:2021 Security Misconfiguration"
  - "A01:2021 Broken Access Control"
cweRefs:
  - "CWE-16"
  - "CWE-250"
  - "CWE-269"
realWorldReferences:
  - title: "OWASP Kubernetes Top 10 — insecure workload configs, over-permissive RBAC, and secret exposure"
    url: "https://owasp.org/www-project-kubernetes-top-ten/"
    type: security_blog
  - title: "Tesla cryptojacking incident — exposed Kubernetes dashboard led to AWS credential theft (RedLock/Unit42 report)"
    url: "https://unit42.paloaltonetworks.com/cryptojacking-cloud/"
    type: incident_postmortem
  - title: "Kubernetes — privileged containers and hostPath escapes; Pod Security Standards (restricted profile) guidance"
    url: "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
    type: security_blog
  - title: "CVE-2020-8554 — man-in-the-middle via Kubernetes ExternalIP services (unauthorized cluster traffic interception)"
    url: "https://github.com/kubernetes/kubernetes/issues/97076"
    type: vendor_security_advisory
quickModeSummary: >
  Review Kubernetes manifests / Helm charts / Kustomize for insecure workload
  configuration. Flag containers running as root or without a securityContext
  (runAsNonRoot, readOnlyRootFilesystem, drop ALL capabilities,
  allowPrivilegeEscalation: false), `privileged: true`, hostPath/hostNetwork/
  hostPID mounts (node-escape surface), secrets baked into env/ConfigMaps or
  manifests in plaintext, over-permissive RBAC (cluster-admin bindings,
  wildcard verbs/resources), missing resource limits (DoS), missing
  NetworkPolicies (flat east-west traffic), and images pinned to `:latest` or
  pulled without digest. The highest-severity items are privileged/hostPath
  containers and cluster-admin RBAC bindings, which turn a single pod
  compromise into full cluster/node takeover.
fileSelectionHint:
  roles: ["manifest", "helm_chart", "kustomize", "rbac", "config"]
  matchImports: []
  matchAuthMapTags: ["kubernetes"]
  maxFiles: 16
  priorityOrder: ["rbac", "manifest", "helm_chart", "kustomize"]
severityHeuristics:
  critical:
    - "A container runs `privileged: true`, or mounts hostPath to a sensitive host path / uses hostNetwork/hostPID, providing a container-to-node escape surface"
    - "An RBAC binding grants cluster-admin (or wildcard verbs on wildcard resources cluster-wide) to a workload service account, so compromising that pod yields full cluster control"
    - "A Secret's value (password, token, cloud credential, private key) is committed in plaintext in a manifest/Helm values/ConfigMap"
  high:
    - "A container has no securityContext restricting privileges: runs as root (no runAsNonRoot/runAsUser), allowPrivilegeEscalation not disabled, or Linux capabilities not dropped"
    - "A service account is auto-mounted (automountServiceAccountToken not disabled) with more permissions than the workload needs, or the default service account is used with non-trivial RBAC"
  medium:
    - "No NetworkPolicy restricts pod-to-pod traffic (flat network enabling lateral movement), or containers lack CPU/memory limits enabling resource-exhaustion DoS of the node"
    - "Images reference mutable tags (:latest or a floating tag) or are pulled without a digest, and/or imagePullPolicy/registry trust is not constrained"
  low:
    - "readOnlyRootFilesystem not set, missing seccomp/AppArmor profile, or liveness/readiness probes and Pod Security Standards labels absent"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:deployment_config"
  relatedNodeIds: ["component:secrets_management", "component:authorization"]
graphEdgeMapping:
  - relation: exposes
    from: "component:deployment_config"
    to: "component:secrets_management"
  - relation: depends_on
    from: "component:deployment_config"
    to: "component:authorization"
commonAiCodingMistakes:
  - "AI generates a Deployment with no securityContext at all, so the container runs as root with default capabilities — the manifest 'works' and looks complete, but a compromised process has root-in-container and an easier path to node escape."
  - "AI adds `privileged: true` or a hostPath mount to solve a 'permission denied' or 'need access to the host' problem, not registering that privileged/hostPath is a direct container-breakout primitive."
  - "AI puts secrets as plaintext `env` values or in a ConfigMap (or hardcodes them in Helm values.yaml) instead of using a Secret sourced from a secrets manager, and commits them to the repo."
  - "AI creates a ClusterRoleBinding to cluster-admin (or a Role with `verbs: [\"*\"]`, `resources: [\"*\"]`) for the app's service account because it's the quickest way past an RBAC error, granting the workload far more than it needs."
  - "AI omits resource requests/limits, allowing a single workload to exhaust node CPU/memory (DoS), and omits NetworkPolicies so every pod can reach every other pod."
  - "AI pins images to `:latest`, making deployments non-reproducible and allowing a poisoned/updated upstream image to be pulled silently — supply-chain and integrity risk."
falsePositiveGuardrails:
  - "Do not flag a workload that sets a restrictive securityContext (runAsNonRoot: true, allowPrivilegeEscalation: false, capabilities drop ALL, readOnlyRootFilesystem where feasible) as insecure — that is the target state. Quote the securityContext present."
  - "Some workloads legitimately need elevated privileges (CNI plugins, node-exporters, storage drivers, ingress controllers) — for infra/system components, confirm whether the privilege is inherent to the component's function before flagging it as an application misconfiguration, and note the elevated trust either way."
  - "A Secret referenced by name (valueFrom.secretKeyRef) with the actual value stored outside the repo (sealed-secrets, external-secrets, SOPS-encrypted) is the correct pattern — only plaintext secret VALUES committed to the repo are exposure."
  - "RBAC scoped to the specific verbs/resources/namespace the workload uses (least privilege) is correct even if it looks verbose — only wildcard or cluster-admin grants are the finding."
  - "hostPath used read-only for a benign, non-sensitive path with a clear purpose is lower risk than a writable hostPath to a sensitive location — assess the path and mount mode, don't treat all hostPath identically."
---

## Root Cause Explanation

Kubernetes defaults are permissive for developer convenience, so security is
almost entirely a function of what the manifests *add* on top of the
defaults. A Deployment with no `securityContext` runs the container as root
with a default set of Linux capabilities — a working, complete-looking
manifest that nonetheless gives any compromised process root-in-container and
a shorter path to escaping onto the node. AI-generated manifests routinely
omit the securityContext entirely because it isn't required to make the pod
run.

The highest-severity failures escalate a single-pod compromise into
cluster-wide or node-wide control. `privileged: true`, `hostPath` mounts,
`hostNetwork`/`hostPID`, and cluster-admin RBAC bindings all collapse the
isolation boundary between the workload and the node/cluster — the Tesla
cryptojacking incident is the canonical example of one exposed component
cascading into cloud-credential theft. AI reaches for these when fighting a
permissions error, treating "make it work" as the goal without recognizing
each is a breakout primitive.

The remaining surface is defense-in-depth that AI omits by default: secrets
committed in plaintext (env/ConfigMap/values.yaml), missing resource limits
(node DoS), missing NetworkPolicies (unrestricted lateral movement), and
mutable image tags (non-reproducible, supply-chain-exposed deployments).

## Vulnerable Patterns

```yaml
# No securityContext → runs as root; privileged + hostPath → node escape
spec:
  containers:
    - name: app
      image: myapp:latest        # mutable tag
      securityContext:
        privileged: true          # breakout primitive
      volumeMounts:
        - { name: host, mountPath: /host }
      env:
        - { name: DB_PASSWORD, value: "s3cr3t-in-plaintext" }  # secret in manifest
  volumes:
    - name: host
      hostPath: { path: / }       # writable host root
---
kind: ClusterRoleBinding          # cluster-admin to a workload SA
roleRef: { kind: ClusterRole, name: cluster-admin }
```

Correct shape hardens the container, sources secrets, and scopes RBAC:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities: { drop: ["ALL"] }
resources:
  limits: { cpu: "500m", memory: "512Mi" }
env:
  - name: DB_PASSWORD
    valueFrom: { secretKeyRef: { name: db-creds, key: password } }
```

## Data Flow Tracing Guide

1. For every Pod/Deployment/StatefulSet/DaemonSet, read the container
   securityContext and pod securityContext. Flag missing runAsNonRoot,
   privileged: true, and host* namespaces/mounts.
2. Inventory hostPath volumes: path sensitivity and read/write mode.
3. Grep for plaintext secret values in env, ConfigMaps, and Helm
   values.yaml; confirm secrets are sourced via secretKeyRef from an external
   store rather than committed.
4. Read Roles/ClusterRoles and their bindings; flag wildcard verbs/resources
   and cluster-admin grants to workload service accounts. Check
   automountServiceAccountToken.
5. Check for resource limits, NetworkPolicies, and image tag/digest pinning.

## Evidence Checklist

- [ ] The manifest file + the exact field (securityContext, privileged,
      hostPath, roleRef, env value) quoted.
- [ ] For RBAC: the Role/ClusterRole rules and the binding to the workload
      service account.
- [ ] For secrets: the plaintext value's location and what it grants.
- [ ] The blast-radius reasoning (pod compromise → node/cluster).

## Attack Scenario Template

> An attacker who achieves code execution in [workload] (via an app
> vulnerability) leverages [privileged: true / hostPath mount / cluster-admin
> service account / plaintext credential in env] defined at [file:line] to
> [escape to the node / read the committed cloud credential / act as
> cluster-admin across all namespaces], turning a single-pod compromise into
> [node takeover / cluster takeover / cloud-account compromise].

## Graph Mapping Instructions

- Ensure a `component:deployment_config` node exists.
- Secret-exposure findings add an `exposes` edge from
  `component:deployment_config` to `component:secrets_management`.
- Privilege/RBAC findings add a `causes`/`enables` edge toward an escalation
  or node/cluster component if the schema supports one.
- Each finding is a `finding:<uuid>` vulnerability node; link findings that
  chain (an app RCE + a privileged container) via `reasoning`.
