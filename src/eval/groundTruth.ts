// Ground-truth seeded vulnerabilities for the sample-repo fixtures under
// tests/fixtures/sample-repos/. Used by scoreFindings() (see scorer.ts) to
// measure precision/recall of real LLM-produced findings against known,
// hand-seeded issues — the harness that closes Winston's biggest credibility
// gap: we previously had no way to tell whether audit findings were actually
// correct or complete.
//
// Keys are the fixture's path relative to the repo root, exactly as passed to
// `winston eval <fixturePath>`. `file` inside each entry is relative to the
// fixture root (i.e. relative to the key), matching how `evidence[].file` is
// reported by the audit pipeline for a scan rooted at that fixture.

export interface GroundTruthEntry {
  file: string;
  lineStart: number;
  lineEnd: number;
  playbookId: string;
  vulnerabilityClass: string;
  description: string;
}

export type GroundTruth = Record<string, GroundTruthEntry[]>;

export const groundTruth: GroundTruth = {
  "tests/fixtures/sample-repos/express-fixture": [
    {
      file: "src/middleware/auth.js",
      lineStart: 5,
      lineEnd: 5,
      playbookId: "ai_security.secrets_management",
      vulnerabilityClass: "hardcoded-secret",
      description:
        'JWT_SECRET falls back to a hardcoded literal ("dev-secret-change-me") when the ' +
        "environment variable is unset, so tokens can be forged in any deployment that " +
        "forgets to set JWT_SECRET.",
    },
    {
      file: "src/middleware/auth.js",
      lineStart: 11,
      lineEnd: 11,
      playbookId: "ai_security.jwt_authentication",
      vulnerabilityClass: "jwt-missing-algorithm-allowlist",
      description:
        "jwt.verify(token, SECRET) is called without an `algorithms` allow-list, " +
        "permitting algorithm-confusion / alg:none style attacks against token verification.",
    },
    {
      file: "src/routes/account.js",
      lineStart: 11,
      lineEnd: 11,
      playbookId: "ai_security.authorization",
      vulnerabilityClass: "missing-authorization",
      description:
        "POST /billing/:userId/refund is a state-changing route mounted without the " +
        "requireAuth middleware, allowing unauthenticated refund requests.",
    },
  ],
  "tests/fixtures/sample-repos/nextjs-fixture": [],
};
