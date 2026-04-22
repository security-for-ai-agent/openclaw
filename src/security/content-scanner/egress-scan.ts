// Egress scanner — applied to the final outbound channel message.
//
// Covers the path where sensitive content reaches the user without going
// through any tool or LLM hook (e.g. a direct memory retrieval). No runId
// correlation is needed — the scan pattern-matches the raw content.

export type EgressClass = "credential-leak" | "pii-exposure";

export type EgressMatch = {
  class: EgressClass;
  kind: string; // e.g. "aws-access-key", "email", "us-ssn"
  pattern: string;
  count: number;
};

export type EgressScanResult = {
  redactedContent: string;
  matches: EgressMatch[];
  criticalHit: boolean;
};

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
  { class: "credential-leak", kind: "aws-access-key", re: /AKIA[0-9A-Z]{16}/g, severity: "soft" },
  { class: "credential-leak", kind: "openai-like-key", re: /\bsk-[A-Za-z0-9]{32,}\b/g, severity: "soft" },
  { class: "credential-leak", kind: "github-pat", re: /\bghp_[A-Za-z0-9]{20,}\b/g, severity: "soft" },
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
  { class: "pii-exposure", kind: "us-ssn", re: /\b\d{3}-\d{2}-\d{4}\b/g, severity: "soft" },
  {
    class: "pii-exposure",
    kind: "credit-card-candidate",
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

function safeCompile(patterns: readonly string[] | undefined, cls: EgressClass): EgressRule[] {
  if (!patterns) {
    return [];
  }
  const out: EgressRule[] = [];
  for (const p of patterns) {
    try {
      out.push({
        class: cls,
        kind: `custom:${p.slice(0, 40)}`,
        re: new RegExp(p, "g"),
        severity: "soft",
      });
    } catch {
      // Ignore invalid operator-supplied regex.
    }
  }
  return out;
}

export function compileEgressRules(cfg: EgressRulesConfig = {}): CompiledEgressRules {
  const rules: EgressRule[] = [];
  if (cfg.enableCredential !== false) {
    rules.push(...DEFAULT_CREDENTIAL_RULES);
  }
  if (cfg.enablePii !== false) {
    rules.push(...DEFAULT_PII_RULES);
  }
  rules.push(...safeCompile(cfg.extraCredentialPatterns, "credential-leak"));
  rules.push(...safeCompile(cfg.extraPiiPatterns, "pii-exposure"));
  return rules;
}

export function scanEgress(content: string, rules: CompiledEgressRules): EgressScanResult {
  if (!content) {
    return { redactedContent: content ?? "", matches: [], criticalHit: false };
  }

  const matches: EgressMatch[] = [];
  let redacted = content;
  let criticalHit = false;

  for (const rule of rules) {
    rule.re.lastIndex = 0;
    let count = 0;
    redacted = redacted.replace(rule.re, () => {
      count++;
      return `[REDACTED:${rule.kind}]`;
    });
    if (count > 0) {
      matches.push({ class: rule.class, kind: rule.kind, pattern: rule.re.source, count });
      if (rule.severity === "hard") {
        criticalHit = true;
      }
    }
  }

  return { redactedContent: redacted, matches, criticalHit };
}
