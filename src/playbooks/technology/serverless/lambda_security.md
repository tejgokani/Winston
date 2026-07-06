---
id: technology.serverless.lambda_security
title: "Serverless: Lambda / Function Security"
category: technology
vulnerabilityClass: broken_access_control
appliesToStack: serverless
requiresAnyTag: ["serverless"]
deepOnly: false
reviewPass: 2
owaspRefs:
  - "A01:2021 Broken Access Control"
  - "A05:2021 Security Misconfiguration"
  - "A08:2021 Software and Data Integrity Failures"
cweRefs:
  - "CWE-285"
  - "CWE-250"
  - "CWE-798"
realWorldReferences:
  - title: "OWASP Serverless Top 10 — event-data injection, over-privileged function roles, and broken authorization"
    url: "https://owasp.org/www-project-serverless-top-10/"
    type: security_blog
  - title: "Denonia — first known malware targeting AWS Lambda, exploiting over-permissioned execution roles (Cado Security)"
    url: "https://www.cadosecurity.com/blog/cado-discovers-denonia-the-first-malware-specifically-targeting-lambda"
    type: incident_postmortem
  - title: "AWS — Lambda function URLs with AuthType NONE expose the function publicly with no IAM auth (AWS docs)"
    url: "https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html"
    type: vendor_security_advisory
  - title: "PureSec / Protego research — event injection across non-HTTP triggers (S3, SNS, DynamoDB streams) in serverless apps"
    url: "https://www.serverless.com/blog/serverless-security-best-practices"
    type: security_blog
quickModeSummary: >
  Review serverless function config (serverless.yml, SAM/template.yaml,
  function handlers) for over-privileged IAM execution roles (the dominant
  serverless risk — each function should have a least-privilege role, not a
  shared `*`/admin role), authorization enforced per function (API Gateway
  authorizers / function-URL AuthType, not AuthType NONE on sensitive
  functions), secrets in plaintext environment variables instead of a secrets
  manager, and event-data injection: functions are triggered not just by HTTP
  but by S3/SNS/SQS/DynamoDB-stream events whose payloads are attacker-
  influenceable and reach injection sinks (shell, SQL, downstream calls)
  without validation. Also watch for missing authorization on individual
  functions when auth is assumed to live 'at the gateway,' and for
  unvalidated trust of event source metadata.
fileSelectionHint:
  roles: ["function", "handler", "iac", "config", "iam"]
  matchImports: ["aws-lambda", "@aws-sdk", "aws-sdk", "serverless"]
  matchAuthMapTags: ["serverless", "jwt"]
  maxFiles: 14
  priorityOrder: ["iam", "config", "handler", "function"]
severityHeuristics:
  critical:
    - "A function's IAM execution role grants wildcard/admin permissions (Action:* / Resource:*, or broad managed admin policy) so a compromise of that function's code yields broad cloud access (the Denonia over-privilege pattern)"
    - "A sensitive function is publicly invokable without authorization — a Lambda function URL with AuthType NONE, or an API Gateway route with no authorizer — exposing privileged logic/data to anyone"
  high:
    - "Event data from any trigger (HTTP body/query, S3 object key/metadata, SNS/SQS message, DynamoDB stream record) reaches an injection sink (shell exec, SQL, a downstream API call, a file path) without validation — serverless event injection"
    - "A secret (API key, DB credential, token) is stored in plaintext in the function's environment variables (visible to anyone with read access to the function config) rather than fetched from a secrets manager"
  medium:
    - "Authorization is assumed to be handled 'at the gateway' but individual functions perform no authorization/ownership check, so any path that invokes the function directly (another trigger, a misconfigured route) bypasses it"
    - "A function trusts event-source identity/metadata (e.g. assumes an S3 event or a JWT claim is authentic) without verifying it, or has an overly long timeout/no concurrency limit enabling cost/DoS amplification"
  low:
    - "Function has broader-than-needed but non-admin permissions, missing structured logging for security events, or dependencies bundled without provenance pinning"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:authorization"
  relatedNodeIds: ["component:secrets_management", "component:api_layer", "component:deployment_config"]
graphEdgeMapping:
  - relation: protects
    from: "component:authorization"
    to: "component:api_layer"
  - relation: exposes
    from: "component:deployment_config"
    to: "component:secrets_management"
commonAiCodingMistakes:
  - "AI gives every function a single shared IAM role with broad permissions (or `*`) because per-function least-privilege roles are more work to define, so any one function's compromise grants access far beyond that function's needs — exactly the over-privilege that Lambda malware like Denonia relies on."
  - "AI configures a Lambda function URL with `AuthType: NONE` (or an API Gateway route with no authorizer) to 'make it callable,' publicly exposing a function that performs privileged actions."
  - "AI treats only the HTTP path as untrusted and validates it, but forgets that S3/SNS/SQS/DynamoDB-stream triggers also carry attacker-influenceable data (an S3 object key, an SNS message body) that flows unvalidated into shell/SQL/downstream sinks — the serverless-specific event-injection surface."
  - "AI puts secrets directly in `environment` variables in serverless.yml/template.yaml, which are readable by anyone with GetFunctionConfiguration and land in plaintext, instead of fetching from Secrets Manager/SSM at runtime."
  - "AI assumes 'the API Gateway authorizer handles auth' and writes functions with zero authorization/ownership logic, so any alternate invocation path (a second trigger, a test route, direct invoke) reaches the logic unauthenticated."
  - "AI trusts claims/metadata in the event (a userId in the JWT payload without verifying the signature at the function, or an assumed-authentic event source) to make authorization decisions."
falsePositiveGuardrails:
  - "Do not flag a function whose IAM role is scoped to the specific actions/resources it uses (least privilege per function) — that is the target. Read the actual policy statements."
  - "A public function URL / no-authorizer route that is intentionally public (a public webhook with its own signature verification, a public health endpoint) is not a finding — confirm signature verification or public-by-design intent."
  - "A function that validates event data from ALL its triggers (not just HTTP) before using it in sinks is correct — confirm which triggers the function has and that each input path is validated, don't assume only HTTP."
  - "Secrets fetched at runtime from Secrets Manager/SSM Parameter Store (SecureString), or injected via a KMS-encrypted mechanism, are not plaintext-env exposure — only literal values in the `environment` block are."
  - "A function relying on an API Gateway authorizer/Cognito/JWT authorizer that genuinely fronts every invocation path is acceptable defense at the edge — flag missing per-function authz only where an alternate invocation path bypasses the edge."
---

## Root Cause Explanation

Serverless changes the shape of the security problem in two ways that
AI-generated code consistently mishandles. First, the security boundary is
the *function's IAM execution role*, not a network perimeter. Every function
runs with a role, and if that role is broad (a shared `*`/admin policy),
compromising any single function — through a dependency, an injection, a
logic bug — grants an attacker whatever the role grants. Least privilege
per function is the core serverless control, and it's precisely the tedious
work AI skips by reusing one permissive role. Lambda-targeting malware like
Denonia exists because over-privileged roles make the payoff worth it.

Second, functions are event-driven, and *events are inputs*. AI reflexively
treats the HTTP request as the untrusted surface but forgets that S3 object
keys, SNS/SQS message bodies, and DynamoDB stream records are equally
attacker-influenceable and flow into the same injection sinks (shell, SQL,
downstream API calls, file paths). This "event injection" surface is unique
to serverless and routinely unvalidated.

Two configuration failures complete the picture. Authorization is often
assumed to live "at the gateway," so individual functions carry no authz
logic — fine until an alternate invocation path (a second trigger, a
function URL with `AuthType: NONE`, a direct invoke) bypasses the gateway.
And secrets get dropped into plaintext environment variables, readable by
anyone who can describe the function config, instead of being fetched from a
secrets manager at runtime.

## Vulnerable Patterns

```yaml
# serverless.yml — shared over-privileged role, public URL, plaintext secret
provider:
  iam:
    role:
      statements:
        - { Effect: Allow, Action: "*", Resource: "*" }   # every function, admin
functions:
  admin:
    handler: handler.admin
    url: { authorizer: NONE }                              # publicly invokable
    environment:
      DB_PASSWORD: "s3cr3t-in-plaintext"                   # readable via config
```

```js
// Event injection from a non-HTTP trigger
export const handler = async (event) => {
  const key = event.Records[0].s3.object.key;              // attacker-influenced
  execSync(`process-file /data/${key}`);                    // shell injection
};
```

Correct shapes scope roles per function, require authorization, fetch
secrets, and validate every event source:

```yaml
functions:
  admin:
    handler: handler.admin
    url: { authorizer: aws_iam }                            # or a JWT authorizer
    iamRoleStatements:
      - { Effect: Allow, Action: ["dynamodb:GetItem"], Resource: "arn:...:table/Users" }
```

```js
const secret = await getSecret("db-password");             // runtime fetch
const key = event.Records[0].s3.object.key;
if (!/^[\w./-]+$/.test(key)) throw new Error("bad key");   // validate event data
```

## Data Flow Tracing Guide

1. For each function, read its IAM role/policy. Flag wildcard/admin grants
   and roles shared across functions with differing needs.
2. Check invocation exposure: function URL AuthType, API Gateway authorizer
   presence, and any alternate triggers that bypass edge auth.
3. Enumerate every trigger a function has (HTTP, S3, SNS, SQS, streams,
   schedule). For each, trace the event payload into the handler and find any
   injection sink it reaches unvalidated.
4. Grep function config for plaintext secrets in `environment`; check for
   runtime secret retrieval instead.
5. Check per-function authorization/ownership logic where edge auth might be
   bypassable.

## Evidence Checklist

- [ ] The function config file + the exact IAM statement / AuthType /
      environment value quoted.
- [ ] For event injection: the trigger, the event field, and the sink it
      reaches, with the missing validation noted.
- [ ] The invocation paths that reach the function and their auth status.
- [ ] The blast-radius reasoning (function compromise → role permissions).

## Attack Scenario Template

> An attacker [invokes the public function URL / places an object in the
> triggering S3 bucket with a crafted key / sends a crafted message to the
> queue]. Because [file:line] [performs no authorization / passes the event
> field into a shell/SQL/downstream sink unvalidated] and the function's role
> [grants Action:* / broad permissions], the attacker [executes the
> privileged logic / injects a command / assumes broad cloud access via the
> function's role], resulting in [impact].

## Graph Mapping Instructions

- Ensure `component:authorization` exists with a `protects` edge to
  `component:api_layer`.
- Over-privileged-role findings add a `depends_on`/`enables` edge toward
  `component:authorization` and note the role's blast radius in `reasoning`.
- Plaintext-secret findings add an `exposes` edge to
  `component:secrets_management`.
- Event-injection findings become `finding:<uuid>` nodes with a `causes` edge
  from the relevant sink component; note the non-HTTP trigger explicitly.
