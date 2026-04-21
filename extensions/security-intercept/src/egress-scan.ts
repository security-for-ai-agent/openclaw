// Egress scanner — Case 1b (memory-retrieval / cache bypass).
//
// Unlike `src/detectors.ts` which runs inside the after_tool_call → prompt-build
// pipeline (keyed by runId), this module runs at `message_sending`, where the
// hook context carries no runId. It therefore does its own pattern match on the
// raw outbound content and returns a per-occurrence redaction plan or a hard
// cancel decision.
//
// Triggering scenario (per openclaw-security/discuss/notes-aemi.md):
//   1. User stored sensitive data in memory BEFORE installing the security plugin.
//   2. After install, a retrieval surfaces that data directly to the user without
//      going through a tool or LLM reasoning step.
//   3. No after_tool_call / tool_result_persist / before_prompt_build fires.
//   4. `message_sending` is the only remaining chokepoint before the channel
//      delivers the reply.

export type EgressClass = "credential-leak" | "pii-exposure";

export type EgressMatch = {
  class: EgressClass;
  kind: string; // e.g. "aws-access-key", "email", "us-ssn"
  pattern: string; // RegExp.source — never the secret itself
  count: number;
};

export type EgressScanResult = {
  redactedContent: string;
  matches: EgressMatch[];
  // `criticalHit` is set when at least one match is classified as a hard-cancel
  // trigger (e.g. private-key PEM blocks). Less severe hits are merely redacted.
  criticalHit: boolean;
};

// Kind → regex + severity.
//
// `hard` = cancel the entire message (private keys, full-PEM blocks — very likely
//          a catastrophic leak if even one line escapes).
// `soft` = redact the matched substring in place, leave the rest of the reply.
type EgressRule = {
  class: EgressClass;
  kind: string;
  re: RegExp;
  severity: "hard" | "soft";
};

export const DEFAULT_CREDENTIAL_RULES: readonly EgressRule[] = [
  {
    class: "credential-leak",
    kind: "private-key-pem",
    re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    severity: "hard",
  },
  {
    class: "credential-leak",
    kind: "aws-access-key",
    re: /AKIA[0-9A-Z]{16}/g,
    severity: "soft",
  },
  {
    class: "credential-leak",
    kind: "openai-like-key",
    re: /\bsk-[A-Za-z0-9]{32,}\b/g,
    severity: "soft",
  },
  {
    class: "credential-leak",
    kind: "github-pat",
    re: /\bghp_[A-Za-z0-9]{20,}\b/g,
    severity: "soft",
  },
  {
    class: "credential-leak",
    kind: "password-assignment",
    re: /(password|passwd|pwd)\s*[:=]\s*([^\s"']{6,})/gi,
    severity: "soft",
  },
  {
    class: "credential-leak",
    kind: "bearer-token",
    re: /\bBearer\s+[A-Za-z0-9._-]{16,}\b/g,
    severity: "soft",
  },
];

export const DEFAULT_PII_RULES: readonly EgressRule[] = [
  {
    class: "pii-exposure",
    kind: "us-ssn",
    re: /\b\d{3}-\d{2}-\d{4}\b/g,
    severity: "soft",
  },
  {
    class: "pii-exposure",
    kind: "credit-card-candidate",
    // 13–19 digits with optional separators; post-filtered with Luhn in caller if desired
    re: /\b(?:\d[ -]?){12,18}\d\b/g,
    severity: "soft",
  },
  {
    class: "pii-exposure",
    kind: "email",
    re: /\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b/g,
    severity: "soft",
  },
];

export type EgressRulesConfig = {
  enableCredential?: boolean;
  enablePii?: boolean;
  extraCredentialPatterns?: readonly string[];
  extraPiiPatterns?: readonly string[];
};

export type CompiledEgressRules = readonly EgressRule[];

function safeCompile(
  patterns: readonly string[] | undefined,
  cls: EgressClass,
  flags = "g",
): EgressRule[] {
  if (!patterns) return [];
  const out: EgressRule[] = [];
  for (const p of patterns) {
    try {
      out.push({ class: cls, kind: `custom:${p.slice(0, 40)}`, re: new RegExp(p, flags), severity: "soft" });
    } catch {
      // ignore invalid — operator-controlled input
    }
  }
  return out;
}

export function compileEgressRules(cfg: EgressRulesConfig = {}): CompiledEgressRules {
  const rules: EgressRule[] = [];
  if (cfg.enableCredential !== false) rules.push(...DEFAULT_CREDENTIAL_RULES);
  if (cfg.enablePii !== false) rules.push(...DEFAULT_PII_RULES);
  rules.push(...safeCompile(cfg.extraCredentialPatterns, "credential-leak"));
  rules.push(...safeCompile(cfg.extraPiiPatterns, "pii-exposure"));
  return rules;
}

export function scanEgress(content: string, rules: CompiledEgressRules): EgressScanResult {
  if (!content) return { redactedContent: content ?? "", matches: [], criticalHit: false };

  const matches: EgressMatch[] = [];
  let redacted = content;
  let criticalHit = false;

  for (const rule of rules) {
    // Each rule may match multiple times; reset lastIndex because re is /g.
    rule.re.lastIndex = 0;
    let count = 0;
    redacted = redacted.replace(rule.re, () => {
      count++;
      return `[REDACTED:${rule.kind}]`;
    });
    if (count > 0) {
      matches.push({
        class: rule.class,
        kind: rule.kind,
        pattern: rule.re.source,
        count,
      });
      if (rule.severity === "hard") criticalHit = true;
    }
  }

  return { redactedContent: redacted, matches, criticalHit };
}
