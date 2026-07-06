---
id: ai_mistakes.destructive_operations_without_safeguards
title: Destructive Operations Without Safeguards
category: ai_mistakes
vulnerabilityClass: ai_coding_defect
appliesToStack: technology-agnostic
deepOnly: false
reviewPass: 1
owaspRefs: []
cweRefs:
  - "CWE-663"
quickModeSummary: >
  Look for irreversible operations (hard deletes, DROP/TRUNCATE, recursive
  file removal, overwrite-in-place, force-push equivalents) run without a
  confirmation step, dry-run, backup, or scoping guard — especially any such
  operation reachable from an AI agent's own tool-use loop or from a
  request handler with attacker-influenced input.
fileSelectionHint:
  roles: ["route_handler", "data_access", "config"]
  matchImports: []
  matchAuthMapTags: []
  maxFiles: 10
  priorityOrder: ["data_access", "route_handler"]
severityHeuristics:
  critical:
    - "A hard-delete/DROP/TRUNCATE/recursive-remove is reachable with attacker- or user-controlled scope (e.g. an id/path parameter) and no ownership check, confirmation, or soft-delete layer"
  high:
    - "Destructive operation runs unconditionally as part of a broader task (e.g. schema migration, cleanup script) with no dry-run flag or backup step, where a scoping bug would delete more than intended"
  medium:
    - "Irreversible write (overwrite-in-place, force update) lacks a version check / optimistic lock, so a race condition can silently discard concurrent changes"
  low:
    - "Destructive action is logged but not otherwise gated (acceptable for internal tooling, but worth flagging for user-facing paths)"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:destructive_operations"
  relatedNodeIds: ["component:data_store"]
graphEdgeMapping:
  - relation: writes
    from: "component:destructive_operations"
    to: "component:data_store"
commonAiCodingMistakes:
  - "AI implements a 'delete' feature as a hard DELETE/DROP because it's the simplest thing that satisfies the request, without asking whether soft-delete, confirmation, or a backup step was intended."
  - "AI agent, given broad shell/file-system tool access to accomplish a task (e.g. 'clean up unused files'), runs a recursive delete scoped more broadly than intended because it inferred the scope from a plausible-looking pattern rather than confirming it precisely."
  - "AI writes a bulk/batch operation (mass update, mass delete) driven by a filter built from user input, without an explicit allow-list or dry-run count check before executing the destructive part."
  - "AI 'fixes' a bug by overwriting a config or data file wholesale instead of making a targeted edit, discarding unrelated content that was already there."
falsePositiveGuardrails:
  - "A destructive operation gated behind an explicit admin-only, authenticated, ownership-checked endpoint with no broader input-controlled scope is standard functionality, not a finding by itself — only flag if the scope/authorization is actually weak (cross-reference the authorization playbook for the auth angle; this playbook is about the missing operational safeguard, e.g. no confirmation/backup/dry-run)."
  - "Test/seed/fixture scripts intended to reset a local dev database are expected to be destructive — only flag if such a script could run against a production target (check for environment guards)."
  - "Soft-delete implementations (status flag, `deleted_at` timestamp) are the safeguard, not the problem — don't flag a soft-delete as if it were a hard delete."
---

## Root Cause Explanation

AI coding agents optimize for completing the stated task with the simplest
correct-looking implementation, and destructive operations (hard delete,
DROP, recursive remove, overwrite) are frequently the most direct way to
satisfy a request like "delete this" or "clean this up." What's missing is
the judgment a careful engineer applies by default: is this reversible? What
happens if the scope is wider than intended due to a bug, a race condition,
or malicious input? Agents with direct tool access (shell, filesystem,
database) compound this because the destructive action can be *executed*
during the agent's own task loop, not just scaffolded as code for a human to
review first.

## Vulnerable Patterns

```js
// Hard delete, no ownership check, no confirmation, no soft-delete
app.delete('/api/documents/:id', async (req, res) => {
  await db.documents.delete({ id: req.params.id })
  res.sendStatus(204)
})
```

```sql
-- Migration runs unconditionally with a filter that could match more
-- rows than intended if the WHERE clause has a bug
DELETE FROM sessions WHERE user_id = $1;
```

```bash
# Agent-executed cleanup with a broad, unconfirmed scope
rm -rf "$TARGET_DIR"/*
```

## Detection Guide

1. Find every hard-delete-equivalent operation (DELETE without a status
   flag, DROP, TRUNCATE, recursive file removal, unconditional overwrite).
2. For each, trace where its scope/target comes from: a hardcoded safe
   value, a validated internal id, or something derived from user/request
   input?
3. Check for the presence of a safeguard: ownership/authorization check
   immediately preceding it, a confirmation step, a dry-run mode, a backup
   taken beforehand, or a soft-delete pattern used instead.
4. For agent/tool-invoked shell or file operations, check whether the target
   path/scope is explicitly and narrowly constructed, or built from a
   pattern/glob that could match more than intended.

## Evidence Checklist

- [ ] Exact destructive call site quoted, with file + line.
- [ ] The source of its scope/target parameter traced to where it's derived.
- [ ] Confirmed no ownership/authorization/confirmation/dry-run safeguard
      exists on this path (checked the surrounding function, not just the
      one line).
- [ ] Confirmed this isn't a dev-only seed/reset script guarded by an
      environment check.

## Failure Scenario Template

> The operation at [file:line] performs an irreversible [delete/overwrite/drop]
> scoped by [parameter], which is sourced from [user input / broad pattern]
> with no [confirmation/backup/dry-run/ownership check] in between. A
> [malicious request | scoping bug | race condition] would cause
> [concrete impact, e.g. "all of another user's documents to be permanently
> deleted" or "the entire sessions table to be dropped"].

## Graph Mapping Instructions

- Create `component:destructive_operations` once per scan if any finding is
  filed here, with a `writes` edge to `component:data_store`.
- Each unsafe destructive operation becomes its own `finding:<uuid>`
  vulnerability node with a `causes` edge from
  `component:destructive_operations`.
