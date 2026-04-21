// Synchronous regex detectors for Case 1a (intercept) threats.
//
// CRITICAL: detection must be synchronous — callers run this before the first
// `await` inside `after_tool_call` so the flag is visible to `tool_result_persist`
// in the same pipeline tick. See hardening-hook-combinations.md §6.

export type ThreatClass = "prompt-injection" | "shell-injection";

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

export type CompiledDetectors = {
  promptInjection: RegExp[];
  shellInjection: RegExp[];
};

export function compileDetectors(
  userPatterns: {
    promptInjection?: readonly string[];
    shellInjection?: readonly string[];
  } = {},
  enabled: { promptInjection?: boolean; shellInjection?: boolean } = {},
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

  for (const re of detectors.promptInjection) {
    if (re.test(text)) {
      return {
        class: "prompt-injection",
        toolName,
        snippet: text.slice(0, 200),
        matchedPattern: re.source,
      };
    }
  }
  for (const re of detectors.shellInjection) {
    if (re.test(text)) {
      return {
        class: "shell-injection",
        toolName,
        snippet: text.slice(0, 200),
        matchedPattern: re.source,
      };
    }
  }
  return null;
}
