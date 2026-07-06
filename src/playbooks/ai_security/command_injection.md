---
id: ai_security.command_injection
title: OS Command Injection
category: ai_security
vulnerabilityClass: command_injection
appliesToStack: technology-agnostic
deepOnly: false
reviewPass: 3
owaspRefs:
  - "A03:2021 Injection"
cweRefs:
  - "CWE-78"
  - "CWE-77"
  - "CWE-88"
realWorldReferences:
  - title: "Node.js — command injection via child_process.spawn/spawnSync on Windows batch files (CVE-2024-27980, April 2024 Security Releases)"
    url: "https://nodejs.org/en/blog/vulnerability/april-2024-security-releases-2"
    type: vendor_security_advisory
  - title: "Node.js third-party modules disclosed on HackerOne: OS Command Injection"
    url: "https://hackerone.com/reports/690010"
    type: bug_bounty_disclosure
  - title: "Ruby disclosed on HackerOne: OS Command Injection via egrep in Rake::FileList"
    url: "https://hackerone.com/reports/651518"
    type: bug_bounty_disclosure
  - title: "Trail of Bits — Prompt injection to RCE in AI agents (argument-injection bypass of command allowlists)"
    url: "https://blog.trailofbits.com/2025/10/22/prompt-injection-to-rce-in-ai-agents/"
    type: security_blog
  - title: "Microsoft Security Blog — When prompts become shells: RCE vulnerabilities in AI agent frameworks (CVE-2026-26030, CVE-2026-25592, Semantic Kernel)"
    url: "https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/"
    type: vendor_security_advisory
  - title: "OWASP OS Command Injection Defense Cheat Sheet"
    url: "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
    type: security_blog
quickModeSummary: >
  Search for child_process.exec/execSync (Node), os.system/subprocess.run(...,
  shell=True)/os.popen (Python), Runtime.exec with a shell (Java), backticks
  or shell=True equivalents in other languages, and any AI-agent "run shell
  command" / "execute tool" implementation. For each hit: is user-controlled
  data concatenated or interpolated into a shell command string (vulnerable),
  or passed as a separate argument to execFile/spawn/subprocess.run(shell=
  False) with an argument array (safe from shell metacharacter injection, but
  still check for argument-injection via flags)? For AI-agent shell tools:
  is there an allowlist of commands, and if so, does it validate arguments/
  flags too, or only the command name?
fileSelectionHint:
  roles: ["api_endpoint", "background_job", "cli_tool", "agent_tool", "route_handler"]
  matchImports: ["child_process", "execa", "shelljs", "subprocess", "os", "commander"]
  matchAuthMapTags: []
  maxFiles: 10
  priorityOrder: ["agent_tool", "api_endpoint", "background_job"]
severityHeuristics:
  critical:
    - "User-controlled input (request body/param, uploaded filename, LLM tool-call argument) is concatenated into a shell-interpreting call (exec/execSync, os.system, subprocess with shell=True) with no metacharacter neutralization, reachable from an unauthenticated or low-privilege endpoint"
    - "An AI agent has a shell/terminal-execution tool where the command string is built (in whole or part) from model output that can be influenced by untrusted content the model ingests (user prompts, fetched web pages, retrieved documents, repo contents) — i.e. prompt injection can reach shell execution"
  high:
    - "Shell-interpreting call is reachable only from an authenticated but non-admin user, or input is partially constrained (e.g. limited to a filename) but the constraint doesn't rule out shell metacharacters or path traversal into a dangerous context"
    - "An agent tool allowlists command names but does not validate arguments/flags, permitting argument-injection into powerful flags (e.g. --exec, --pre, -x on otherwise 'safe' allowlisted binaries) that achieve code execution without ever invoking a disallowed command"
  medium:
    - "execFile/spawn is used correctly (argument array, no shell) but with a Windows target and no explicit `shell:false`/no `.bat`/`.cmd` guard, exposing the CVE-2024-27980-class batch-file argument injection on Windows"
    - "Input is validated with a denylist/regex blocklist of shell metacharacters instead of an allowlist of expected characters — denylists are routinely bypassable and OWASP explicitly recommends against them"
  low:
    - "Shell command construction is present but every input is a fixed, hardcoded, or enum-constrained value with no attacker-reachable path to influence it — flag for defense-in-depth (prefer execFile/spawn) but do not treat as an active vulnerability"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:command_injection"
  relatedNodeIds: ["component:input_validation", "component:agent_tooling", "component:api_security"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:agent_tooling"
    to: "component:command_injection"
  - relation: protects
    from: "component:command_injection"
    to: "component:host_system"
commonAiCodingMistakes:
  - "AI reaches for child_process.exec()/execSync() or Python's os.system()/subprocess.run(..., shell=True) when scaffolding a 'run this command' feature, because it's the shortest path to 'shell out and get output back,' and builds the command via string concatenation or an f-string/template literal with a user-supplied value spliced in — this is the exact shape behind the HackerOne #690010 (Node.js third-party modules) and #651518 (Ruby/Rake egrep) disclosures."
  - "AI implements input 'sanitization' for a shell command by blocklisting a few characters (e.g. stripping `;` and `&&`) instead of avoiding the shell entirely — OWASP's guidance is explicit that denylists of shell metacharacters are incomplete (backticks, `$()`, `|`, newlines, and encoding tricks are routinely missed) and that the only reliable defense is not invoking a shell at all (execFile/spawn with an argument array, or subprocess.run with shell=False and a list)."
  - "AI scaffolds an AI-agent 'shell tool' / 'run command' tool definition (a common pattern in agentic coding assistants and MCP servers) that lets the model construct and execute an arbitrary command string, trusting that the model's own judgment is a sufficient safety boundary — but any untrusted content the model later ingests (a fetched webpage, a file in the repo, a user message) can prompt-inject the model into emitting a malicious command through that same tool, as documented in Trail of Bits' and Microsoft's 2025-2026 AI-agent RCE research."
  - "AI builds a command allowlist for an agent tool (only allow `git`, `ls`, `grep`, `find`, etc.) and considers the job done, without validating the *arguments* passed to those allowlisted binaries — Trail of Bits documented that flags like `git show --output`, `rg --pre`, and `fd -x` turn 'safe' allowlisted commands into arbitrary code execution primitives, and that this argument-injection (CWE-88) bypass evades allowlist-based and human-approval-gated designs alike."
  - "AI uses execFile/spawn correctly (no shell, argument array) on the happy path, but then adds a Windows-compatibility shim that special-cases `.bat`/`.cmd` scripts by re-enabling `shell: true` or invoking `cmd.exe /c` with the same concatenated string, reintroducing the exact vulnerability class Node.js patched in CVE-2024-27980."
  - "AI passes user input into a templated shell command for a 'convenience' feature (e.g. an image-processing pipeline calling out to ImageMagick/ffmpeg with a filename or URL parameter) without recognizing that the filename/URL itself is attacker-controlled, because the review only considered the primary form input and missed the secondary parameter riding along in the same request."
falsePositiveGuardrails:
  - "Do not flag child_process.execFile/spawn (Node), subprocess.run/Popen with a list and shell=False (Python), or ProcessBuilder with separate command/argument entries (Java) as command injection purely for shelling out — these APIs pass arguments directly to the OS without shell interpretation, which is the OWASP-recommended primary defense. Check instead whether the *arguments themselves* are further interpreted by the invoked program in a dangerous way (argument injection, e.g. a filename argument starting with `-` being read as a flag) before downgrading or dismissing."
  - "Do not treat every use of exec()/os.system()/shell=True as an automatic finding — trace whether the command string is built entirely from fixed, hardcoded, or enum/allowlist-constrained values with no attacker-reachable input; if so this is a defense-in-depth/hygiene note (prefer execFile/spawn), not an active vulnerability, and should be capped at low severity."
  - "For AI-agent 'run shell command' tools, do not stop at 'there is a command allowlist, so this is safe' — per the Trail of Bits research, confirm whether arguments/flags to allowlisted commands are also validated (not just the command name), since argument injection on an allowlisted binary is the documented real-world bypass pattern."
  - "Do not conflate this playbook with SQL injection, template injection, or code injection (eval/exec of application code) — command injection specifically means influencing what the *operating system shell or process* executes; if the sink is a database driver, a template engine, or a language `eval`, cite the more specific vulnerability class instead."
  - "A shell metacharacter denylist/escaping function (e.g. a hand-rolled `escapeShellArg`-style helper) reduces but does not eliminate risk — do not downgrade severity to 'safe' solely because escaping is present; verify the escaping function actually covers the target shell's full metacharacter set (this is exactly the kind of narrow, incomplete fix OWASP warns is easy to get wrong) or confirm the code has migrated to the argument-array APIs instead."
  - "Do not flag command construction that runs only in a locked-down, non-interactive CI/build context with no attacker-reachable trigger (e.g. a fixed lint script invoked with hardcoded arguments in a package.json script) — confirm there is a realistic path for an external or lower-privilege actor to influence the command before treating it as a live vulnerability."
---

## Root Cause Explanation

OS command injection (CWE-78, and its argument-injection cousin CWE-88)
happens when an application builds a string that is handed to a shell for
interpretation, and part of that string is attacker-influenced. The shell
doesn't distinguish "the command I meant to run" from "extra commands the
attacker smuggled in" — metacharacters like `;`, `&&`, `|`, backticks, and
`$()` are all the shell needs to chain in arbitrary additional commands, and
the injected commands run with whatever privileges the parent process has.

This is one of the highest-impact classes a reviewer can find, because
unlike XSS (browser-scoped) or most injection classes, a successful command
injection typically hands the attacker code execution on the host itself —
file system access, network access, credential theft from environment
variables, and a pivot point into the rest of the infrastructure.

Three variants matter for this playbook:

1. **Classic shell-string injection.** `child_process.exec`/`execSync`,
   `os.system`, `subprocess.run(..., shell=True)`, `os.popen`, backtick/
   `Runtime.exec` invocations with a shell — any API that hands a full
   string to `/bin/sh -c` (or `cmd.exe /c` on Windows) is inherently
   vulnerable the moment attacker-influenced data reaches that string
   unescaped. The safe alternative — `execFile`/`spawn` with an argument
   array, or `subprocess.run([...], shell=False)` — bypasses the shell
   entirely, so metacharacters in an individual argument are inert.
2. **Argument injection on "safe" APIs.** Even when a codebase correctly
   avoids the shell, passing attacker-influenced data as an *argument* to a
   binary can still be dangerous if that argument can itself be interpreted
   as a flag (e.g. a filename starting with `-` or `--`) by the invoked
   program. Trail of Bits' 2025 research on AI coding agents formalized this
   as the dominant real-world bypass for command-allowlist defenses: the
   shell is never invoked, the command name is on the allowlist, and the
   attack still achieves code execution purely through flag misuse
   (`git show --output`, `rg --pre`, `fd -x`, `go test -exec`).
3. **AI-agent "run shell command" tools.** Agentic coding tools and MCP
   servers increasingly expose a shell-execution or terminal tool to the
   model. The trust boundary here is different from classic injection: the
   "attacker input" isn't necessarily a web form field, it's *anything the
   model's context window can contain* — a user's prompt, but also a fetched
   webpage, a file in the repository being reviewed, a code comment, or tool
   output the model reads back. If any of that content can steer what
   command the model asks the tool to run, and the tool executes it (or lets
   allowlisted-but-unvalidated arguments through), that's command injection
   with an LLM as the confused deputy in the middle — the pattern Microsoft's
   Semantic Kernel disclosures (CVE-2026-26030, CVE-2026-25592) and Trail of
   Bits' agent research both document.

## Vulnerable Patterns

Look for shapes like these (illustrative, not exhaustive — reason about
equivalents in the actual stack you're reviewing, don't string-match):

```js
// Node.js — string-concatenated user input into a shell-interpreting call
const { exec } = require('child_process');
exec(`convert ${req.body.filename} output.png`, callback); // filename is attacker-controlled

// Safe equivalent: execFile with an argument array, no shell
const { execFile } = require('child_process');
execFile('convert', [filename, 'output.png'], callback);
```

```python
# Python — os.system / subprocess with shell=True and unsanitized input
import os
os.system(f"ping -c 4 {request.args['host']}")  # host is attacker-controlled

import subprocess
subprocess.run(f"tar -xf {user_supplied_path}", shell=True)  # shell=True + f-string

# Safe equivalent: argument list, shell=False (the default)
subprocess.run(["tar", "-xf", user_supplied_path])
```

```js
// AI-agent shell tool — model-constructed command string executed directly
async function runShellTool(commandFromModel) {
  const { stdout } = await exec(commandFromModel); // no allowlist, no arg validation
  return stdout;
}

// Even with an allowlist, argument injection can still achieve RCE:
// e.g. allowlisting "git" but not validating flags lets a model (possibly
// steered by injected content) run `git show --output=/tmp/x.sh ...`
// followed by a second allowlisted call that executes the written file.
```

```java
// Java — Runtime.exec with a shell-interpreted string
Runtime.getRuntime().exec("sh -c \"nslookup " + userInput + "\"");
```

## Data Flow Tracing Guide

To evaluate this playbook responsibly, trace the following before writing any
Finding:

1. Find every process-spawning call: `child_process.exec`/`execSync`,
   `os.system`, `os.popen`, `subprocess.run`/`Popen`/`call`/`check_output`
   (check the `shell=` argument), `Runtime.exec`, `ProcessBuilder` (check
   whether it's given a single string vs. separate arguments), and any
   AI-agent tool/function whose description implies shell/terminal access.
2. For each call, determine whether it invokes a shell. `exec`/`execSync`
   (Node), `shell=True` (Python), a single interpolated string handed to
   `Runtime.exec` or `ProcessBuilder` — all shell-interpreting. `execFile`/
   `spawn` with an array (Node), `shell=False` with a list (Python,
   default), `ProcessBuilder` with separate arguments — not shell-
   interpreting for metacharacters, but still check step 4.
3. For shell-interpreting calls: trace every piece of the command string
   backward to its source. Is any segment attacker-influenced (request
   body/query/header, uploaded filename, database value originally supplied
   by a user, LLM tool-call output whose context could include untrusted
   content)? Cite the exact variable and its origin.
4. For non-shell calls (execFile/spawn/shell=False): check whether any
   individual argument is attacker-influenced *and* could be interpreted as
   a flag by the target program (starts with `-`/`--`, or the program has a
   documented dangerous flag like `--exec`, `--output`, `-x`, `--pre`). This
   is the argument-injection variant and is not mitigated by avoiding the
   shell.
5. For AI-agent tools specifically: identify what the tool's system
   prompt/description claims it does, what the actual implementation
   executes, whether there's a command allowlist, and — critically — whether
   arguments/flags are validated in addition to the command name. Then trace
   backward: can any part of the model's context (retrieved content, fetched
   pages, repo files, prior tool outputs) influence what the model requests
   the tool to run? If so, that's the injection vector, even without a
   traditional "user input" field.
6. Check for a Windows-specific `.bat`/`.cmd` code path using `spawn`/
   `spawnSync` without confirming `shell` is explicitly and correctly set —
   this is the CVE-2024-27980 pattern.

## Evidence Checklist

Before submitting a Finding for this playbook, confirm:

- [ ] At least one concrete code snippet with an exact file + line range is
      attached as evidence — the exact process-spawning call site, not a
      paraphrase.
- [ ] The attacker-controlled input is identified by name and origin (which
      request field, tool parameter, or upstream content source it is).
- [ ] Whether the call is shell-interpreting or argument-array-based is
      stated explicitly, since this determines whether the finding is
      classic shell injection (CWE-78) or argument injection (CWE-88).
- [ ] For AI-agent tool findings: the tool's allowlist/validation logic (or
      absence of it) is cited, and the path by which untrusted content could
      reach the model's tool-call arguments is described concretely.
- [ ] Confirmation that a realistic attacker-reachable path exists into the
      command (not a hardcoded, enum-constrained, or CI-internal-only value).

A finding without at least one concrete code-snippet evidence entry must not
be submitted.

## Attack Scenario Template

> An attacker controls [specific input — a request parameter / uploaded
> filename / a webpage the AI agent fetches / a repo file the agent reads]
> which reaches [specific code location] as part of a command executed via
> [exec/execSync/os.system/subprocess shell=True/an AI-agent shell tool].
> Because [missing validation/allowlist/argument check], the attacker injects
> [shell metacharacters / a malicious flag on an allowlisted binary /
> a fabricated instruction the model reproduces into the tool call],
> resulting in [concrete impact specific to this repo — e.g. "arbitrary
> command execution as the application's service account, including read
> access to environment variables containing database credentials" or
> "the coding agent writing and then executing an attacker-supplied script
> on the developer's machine"].

Fill every bracket concretely from evidence gathered in this repo. If a
bracket can't be filled from real evidence, the scenario is speculative and
severity must be capped at `medium`, with a note that exploitability is
unconfirmed.

## Graph Mapping Instructions

- Always ensure a `component:command_injection` node exists (create it on
  the first command-injection-related finding in a scan) with a
  `depends_on` edge from `component:agent_tooling` (for AI-agent shell
  tools) or the relevant `component:api_security`/`component:background_job`
  node for classic server-side injection.
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type
  `vulnerability`, with a `causes` edge from `component:command_injection`
  to the finding node.
- If a finding grants the attacker code execution on the host, add an
  `enables` edge from the finding node to `component:host_system` (and, if
  applicable, to any downstream component reachable from that host — e.g.
  `component:secrets`/`component:database` if environment variables or local
  credentials would be exposed).
- For AI-agent-tool findings, add a `depends_on` edge from
  `component:agent_tooling` to `component:command_injection` and note in the
  finding's `reasoning` field whether the root cause is missing shell
  avoidance, missing argument validation on an allowlist, or an untrusted-
  content-to-tool-call path, so the graph mapper can distinguish root cause
  from symptom when multiple findings share the same underlying tool.
