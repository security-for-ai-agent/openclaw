// Synchronous regex detectors for Case 1a (intercept) threats.
//
// CRITICAL: detection must be synchronous — callers run this before the first
// `await` inside `after_tool_call` so the flag is visible to `tool_result_persist`
// in the same pipeline tick. See hardening-hook-combinations.md §6.

export type ThreatClass =
  | "prompt-injection" // Case 1a
  | "shell-injection" // Case 1a
  | "credential-leak" // Case 2 (tool-origin; Case 1b egress is handled by egress-scan.ts)
  | "scope-expansion" // Case 2
  | "oversized-result"; // Case 2

/** Which combo a detected class takes. */
export type Case = "1a" | "2";

/**
 * Class → Case routing used by hooks.ts to pick the right transcript, guide,
 * and gate behavior per-detection.
 *
 *   1a (intercept)     — content REPLACED, hard BLOCK on follow-on tools, strict directive.
 *   2  (prompt-modify) — content KEPT + annotated, requireApproval or no gate, softer directive.
 */
export const CASE_BY_CLASS: Readonly<Record<ThreatClass, Case>> = {
  "prompt-injection": "1a",
  "shell-injection": "1a",
  "credential-leak": "2",
  "scope-expansion": "2",
  "oversized-result": "2",
};

export function caseOf(cls: ThreatClass): Case {
  return CASE_BY_CLASS[cls];
}

export type Detection = {
  class: ThreatClass;
  toolName: string;
  toolCallId?: string;
  runId?: string;
  snippet: string;
  matchedPattern: string;
  timestamp: number;
};

export const DEFAULT_PROMPT_INJECTION_PATTERNS: RegExp[] = [
  /ignore (?:all |the )?previous (?:instructions|rules|directives)/i,
  /disregard (?:your|all|any) (?:prior|previous|system) (?:instructions|rules|directives|prompt)/i,
  /you are now (?:a|an) [a-z\s-]{3,40}(?:assistant|bot|agent|mode)/i,
  /forget (?:everything|all) (?:you|that) (?:were told|know)/i,
  /new persona[:\s]/i,
  /system prompt[:\s].{0,80}override/i,
];

export const DEFAULT_SHELL_INJECTION_PATTERNS: RegExp[] = [
  /\brm\s+-rf\s+\/(?:\s|$)/,
  /\bcurl\b[^|]*\|\s*(?:sh|bash|zsh|ksh)\b/,
  /\bwget\b[^|]*\|\s*(?:sh|bash|zsh|ksh)\b/,
  /:\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:/, // fork bomb
  /\bmkfs\./,
  /\bdd\s+if=\/dev\/(?:zero|random)\s+of=\//,
  /\bDROP\s+(?:TABLE|DATABASE|SCHEMA)\b/i,
  />\s*\/etc\/(?:passwd|shadow|hosts)/,
];

// Case 2 classes — content is KEPT with inline annotation; LLM is guided, not gagged.
export const DEFAULT_CREDENTIAL_LEAK_PATTERNS: RegExp[] = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /AKIA[0-9A-Z]{16}/,
  /\bsk-[A-Za-z0-9]{32,}\b/,
  /\bghp_[A-Za-z0-9]{20,}\b/,
  /(?:password|passwd|pwd)\s*[:=]\s*\S{6,}/i,
  /\bBearer\s+[A-Za-z0-9._-]{16,}\b/,
];

export const DEFAULT_SCOPE_EXPANSION_PATTERNS: RegExp[] = [
  /you (?:can|should|must) also (?:execute|run|access|read|write|delete)/i,
  /additionally,?\s*you (?:are|now have|may)/i,
  /your new role(?:\s+is|\s*[:\s])/i,
  /you now have (?:access to|permission to|authority to)/i,
  /from now on,? you (?:are|may|can) /i,
];

/** Threshold above which a tool result is flagged `oversized-result`. */
export const DEFAULT_OVERSIZED_THRESHOLD = 8_000;

export type CompiledDetectors = {
  promptInjection: RegExp[];
  shellInjection: RegExp[];
  credentialLeak: RegExp[];
  scopeExpansion: RegExp[];
  oversizedThreshold: number;
  oversizedEnabled: boolean;
};

export type DetectorsConfig = {
  promptInjection?: readonly string[];
  shellInjection?: readonly string[];
  credentialLeak?: readonly string[];
  scopeExpansion?: readonly string[];
};

export type DetectorsEnabledFlags = {
  promptInjection?: boolean;
  shellInjection?: boolean;
  credentialLeak?: boolean;
  scopeExpansion?: boolean;
  oversizedResult?: boolean;
  oversizedThreshold?: number;
};

export function compileDetectors(
  userPatterns: DetectorsConfig = {},
  enabled: DetectorsEnabledFlags = {},
): CompiledDetectors {
  const safeCompile = (patterns?: readonly string[]): RegExp[] => {
    if (!patterns) return [];
    const compiled: RegExp[] = [];
    for (const p of patterns) {
      try {
        compiled.push(new RegExp(p));
      } catch {
        // ignore invalid — operator-controlled input; log is emitted by caller
      }
    }
    return compiled;
  };

  return {
    promptInjection:
      enabled.promptInjection === false
        ? []
        : [...DEFAULT_PROMPT_INJECTION_PATTERNS, ...safeCompile(userPatterns.promptInjection)],
    shellInjection:
      enabled.shellInjection === false
        ? []
        : [...DEFAULT_SHELL_INJECTION_PATTERNS, ...safeCompile(userPatterns.shellInjection)],
    credentialLeak:
      enabled.credentialLeak === false
        ? []
        : [...DEFAULT_CREDENTIAL_LEAK_PATTERNS, ...safeCompile(userPatterns.credentialLeak)],
    scopeExpansion:
      enabled.scopeExpansion === false
        ? []
        : [...DEFAULT_SCOPE_EXPANSION_PATTERNS, ...safeCompile(userPatterns.scopeExpansion)],
    oversizedThreshold: enabled.oversizedThreshold ?? DEFAULT_OVERSIZED_THRESHOLD,
    oversizedEnabled: enabled.oversizedResult !== false,
  };
}

function resultToText(result: unknown): string {
  if (typeof result === "string") return result;
  if (result == null) return "";
  try {
    return JSON.stringify(result);
  } catch {
    return String(result);
  }
}

export function detect(
  toolName: string,
  result: unknown,
  detectors: CompiledDetectors,
): Omit<Detection, "toolCallId" | "runId" | "timestamp"> | null {
  const text = resultToText(result);
  if (text.length === 0) return null;

  // Ordering: the sharpest Case 1a attacks first (the LLM must never see them),
  // then the Case 2 informational/guidance classes. First match wins; the
  // chosen class determines whether hooks.ts takes a Case 1a or Case 2 branch.

  for (const re of detectors.promptInjection) {
    if (re.test(text))
      return { class: "prompt-injection", toolName, snippet: text.slice(0, 200), matchedPattern: re.source };
  }
  for (const re of detectors.shellInjection) {
    if (re.test(text))
      return { class: "shell-injection", toolName, snippet: text.slice(0, 200), matchedPattern: re.source };
  }
  for (const re of detectors.credentialLeak) {
    if (re.test(text))
      return { class: "credential-leak", toolName, snippet: text.slice(0, 200), matchedPattern: re.source };
  }
  for (const re of detectors.scopeExpansion) {
    if (re.test(text))
      return { class: "scope-expansion", toolName, snippet: text.slice(0, 200), matchedPattern: re.source };
  }
  if (detectors.oversizedEnabled && text.length > detectors.oversizedThreshold) {
    return {
      class: "oversized-result",
      toolName,
      snippet: text.slice(0, 200),
      matchedPattern: `length>${detectors.oversizedThreshold}`,
    };
  }
  return null;
}
