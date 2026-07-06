---
id: technology.terraform.iac_security
title: "Terraform: Infrastructure-as-Code Security"
category: technology
vulnerabilityClass: security_misconfiguration
appliesToStack: terraform
requiresAnyTag: ["terraform"]
deepOnly: false
reviewPass: 2
owaspRefs:
  - "A05:2021 Security Misconfiguration"
  - "A01:2021 Broken Access Control"
cweRefs:
  - "CWE-16"
  - "CWE-732"
  - "CWE-798"
realWorldReferences:
  - title: "Capital One 2019 breach — SSRF plus an over-permissive IAM role on a WAF instance exfiltrated 100M records from S3 (US Senate report)"
    url: "https://www.congress.gov/116/meeting/house/110236/documents/HHRG-116-BA00-20191001-SD002.pdf"
    type: incident_postmortem
  - title: "OWASP Infrastructure as Code Security cheat sheet — misconfigurations, secrets in state, and drift"
    url: "https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html"
    type: security_blog
  - title: "HashiCorp — sensitive data in Terraform state files is stored in plaintext; guidance on state backend encryption and secret handling"
    url: "https://developer.hashicorp.com/terraform/language/state/sensitive-data"
    type: vendor_security_advisory
  - title: "tfsec / Trivy — canonical Terraform misconfiguration checks (public S3, open security groups, unencrypted storage)"
    url: "https://aquasecurity.github.io/tfsec/latest/checks/"
    type: security_blog
quickModeSummary: >
  Review Terraform (.tf) for cloud misconfigurations that expose data or grant
  excessive access. Flag: security groups / firewall rules open to 0.0.0.0/0
  on sensitive ports (SSH 22, RDP 3389, database ports), object storage made
  public (S3 public ACL/policy, `block_public_access` disabled), unencrypted
  storage/volumes/databases (encryption not enabled, no KMS), IAM policies
  with `Action: "*"`/`Resource: "*"` or wildcard admin, hardcoded secrets/
  credentials/private keys in .tf or committed .tfvars, public database
  instances (`publicly_accessible = true`), and disabled logging/audit (no
  CloudTrail / flow logs / access logging). The Capital One breach —
  over-permissive IAM plus a public entry point — is the archetype these
  checks defend against.
fileSelectionHint:
  roles: ["iac", "terraform", "config", "module"]
  matchImports: []
  matchAuthMapTags: ["terraform"]
  maxFiles: 16
  priorityOrder: ["module", "iac", "config"]
severityHeuristics:
  critical:
    - "An IAM policy/role grants wildcard admin (Action: \"*\" on Resource: \"*\", or *:* / AdministratorAccess) to a resource reachable from a public entry point, reproducing the Capital One over-permissioned-role pattern"
    - "Object storage is made public (S3 bucket public ACL/policy, block_public_access = false / all four flags disabled) on a bucket holding non-public data"
    - "A hardcoded secret, cloud credential, private key, or password appears literally in a .tf file or a committed .tfvars"
  high:
    - "A security group / firewall rule allows 0.0.0.0/0 (or ::/0) to a sensitive port — SSH (22), RDP (3389), or a database port (5432/3306/27017/6379) — exposing admin/data access to the internet"
    - "A managed database or storage resource is created with encryption-at-rest disabled or is publicly_accessible = true"
  medium:
    - "An IAM policy is over-broad but not full admin (wildcards scoped to a service, or broad action lists beyond least privilege), or a resource lacks encryption-in-transit enforcement (no TLS/HTTPS-only policy)"
    - "Audit/flow/access logging is disabled or not configured for security-relevant resources (CloudTrail, VPC flow logs, S3/LB access logs)"
  low:
    - "Terraform state backend is unencrypted or local (sensitive values live in state in plaintext), tags/versioning/deletion-protection are missing, or provider/module versions are unpinned"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:deployment_config"
  relatedNodeIds: ["component:secrets_management", "component:authorization", "component:data_store"]
graphEdgeMapping:
  - relation: exposes
    from: "component:deployment_config"
    to: "component:data_store"
  - relation: depends_on
    from: "component:deployment_config"
    to: "component:authorization"
commonAiCodingMistakes:
  - "AI writes a security group with `cidr_blocks = [\"0.0.0.0/0\"]` on port 22 or a database port because it's the fastest way to make connectivity 'just work,' exposing SSH/DB directly to the internet."
  - "AI creates an S3 bucket and either sets a public-read ACL/policy or omits the `aws_s3_bucket_public_access_block` (leaving public access possible), so data intended to be private is world-readable."
  - "AI attaches an IAM policy with `Action = \"*\"` and `Resource = \"*\"` (or `AdministratorAccess`) to an instance/role to get past a permissions error, granting far more than the workload needs — the exact Capital One failure when combined with a public-facing entry point."
  - "AI hardcodes a secret/access key/password directly in a .tf resource argument or a committed .tfvars, not using a secrets manager data source or a variable sourced from the environment/vault — and it also lands in plaintext Terraform state."
  - "AI provisions an RDS/managed database with `publicly_accessible = true` and/or `storage_encrypted = false`, exposing the database to the internet and storing data unencrypted at rest."
  - "AI omits CloudTrail / VPC flow logs / access logging, leaving no audit trail of the access the other misconfigurations enable."
falsePositiveGuardrails:
  - "Do not flag a 0.0.0.0/0 rule on ports genuinely meant to be public (80/443 on a public web/load balancer, a public CDN origin) — the concern is administrative/data ports (22, 3389, DB ports) or unexpectedly-broad access. Assess the port and resource role."
  - "IAM policies scoped to specific actions and resource ARNs (least privilege) are correct even when verbose — only wildcard admin or clearly-excessive grants are findings. Read the actual actions/resources."
  - "A secret referenced via a data source (aws_secretsmanager_secret, vault_generic_secret) or a variable with no default that is supplied at apply time from a secure source is the correct pattern — only literal hardcoded values (or committed .tfvars with real secrets) are exposure."
  - "A bucket/resource that is intentionally public with a documented reason (static website assets, public data set) and appropriate other controls is not automatically a finding — confirm the data classification."
  - "encryption enabled via a default (some providers/resources encrypt by default) is not missing encryption — verify the provider default before flagging, and cite the specific argument."
---

## Root Cause Explanation

Terraform makes cloud infrastructure a code artifact, which means cloud
misconfigurations become code review findings — and the misconfigurations
that matter most are the ones that either expose data directly to the
internet or grant a compromised component more access than it needs. The
Capital One breach is the archetype: a server-side request forgery gave an
attacker a foothold, and an over-permissive IAM role attached to that
component let the foothold read 100 million records out of S3. Neither the
SSRF nor the IAM role alone was catastrophic; the combination was. IaC review
is where you catch the IAM half — and the public-exposure half — before they
compose with an application bug.

AI-generated Terraform gravitates toward "make it connect / make it work":
`0.0.0.0/0` on SSH or a database port, a public S3 bucket (or an omitted
`public_access_block`), `Action = "*"` IAM to clear a permissions error,
`publicly_accessible = true` on a database, and encryption left off because
it isn't required for `apply` to succeed. Each is a one-line convenience with
outsized blast radius. Hardcoded secrets compound the problem twice over: once
in the repo, and again in Terraform state, which stores values in plaintext.

## Vulnerable Patterns

```hcl
# SSH open to the world + public DB + unencrypted + wildcard IAM
resource "aws_security_group_rule" "ssh" {
  type = "ingress" from_port = 22 to_port = 22 protocol = "tcp"
  cidr_blocks = ["0.0.0.0/0"]                       # SSH to the internet
}

resource "aws_db_instance" "db" {
  publicly_accessible = true                        # DB reachable publicly
  storage_encrypted   = false                       # unencrypted at rest
  password            = "P@ssw0rd-hardcoded"        # secret in .tf + state
}

resource "aws_iam_role_policy" "app" {
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] })
}
```

Correct shapes scope access, encrypt, and source secrets:

```hcl
resource "aws_security_group_rule" "ssh" {
  type = "ingress" from_port = 22 to_port = 22 protocol = "tcp"
  cidr_blocks = ["10.0.0.0/8"]                      # internal only / bastion
}

resource "aws_db_instance" "db" {
  publicly_accessible = false
  storage_encrypted   = true
  kms_key_id          = aws_kms_key.db.arn
  password            = data.aws_secretsmanager_secret_version.db.secret_string
}
# IAM policy: explicit actions + resource ARNs, not "*"
```

## Data Flow Tracing Guide

1. Grep every ingress/firewall rule for `0.0.0.0/0` and `::/0`; classify the
   port (public web vs. admin/DB) and the resource it protects.
2. Inventory object storage: public ACL/policy, and presence/config of
   public-access-block. Inventory databases/volumes for encryption and
   `publicly_accessible`.
3. Read every IAM policy/role document; flag `"*"` actions/resources and
   admin managed policies, and note which are attached to internet-facing
   components.
4. Grep for literal secrets/keys/passwords in .tf and committed .tfvars, and
   check how secrets are otherwise sourced.
5. Check logging/audit resources and the state backend's encryption.

## Evidence Checklist

- [ ] The .tf file + the exact resource/argument (cidr_blocks, public ACL,
      IAM statement, publicly_accessible, hardcoded value) quoted.
- [ ] For IAM: the actions/resources granted and the component the role
      attaches to.
- [ ] The data classification / port role justifying severity.
- [ ] The composition risk where an over-permissive role meets a public
      entry point (Capital One pattern), if applicable.

## Attack Scenario Template

> An attacker [reaches the resource directly over the internet via the
> 0.0.0.0/0 rule / reads the public bucket / after gaining a foothold in a
> component, assumes its over-permissive IAM role] defined at [file:line], and
> because [the port is a DB/SSH port / the bucket holds private data / the
> role grants Action:* on Resource:*], [exfiltrates the data / gains
> administrative control of the account], with impact amplified by [missing
> encryption / no audit logging to detect it].

## Graph Mapping Instructions

- Ensure a `component:deployment_config` node exists.
- Public-exposure / storage findings add an `exposes` edge from
  `component:deployment_config` to `component:data_store`.
- Over-permissive IAM findings add a `depends_on`/`enables` edge toward
  `component:authorization` and, where they compose with an app entry point,
  note the chain in `reasoning`.
- Secret-in-code findings add an `exposes` edge to
  `component:secrets_management`.
