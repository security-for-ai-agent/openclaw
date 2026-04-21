// Security audit collector — feeds `openclaw security audit` / `openclaw doctor`.

import type {
  OpenClawPluginSecurityAuditCollector,
  OpenClawPluginSecurityAuditContext,
} from "openclaw/plugin-sdk/plugin-entry";

import type { PluginConfig } from "./hooks.js";

// SecurityAuditFinding is not re-exported through plugin-sdk/plugin-entry;
// mirror its shape locally (authoritative definition in src/security/audit.types.ts).
type SecurityAuditFinding = {
  checkId: string;
  severity: "info" | "warn" | "critical";
  title: string;
  detail: string;
  remediation?: string;
};

const PLUGIN_ID = "security-intercept";

export const securityInterceptAuditCollector: OpenClawPluginSecurityAuditCollector = (
  ctx: OpenClawPluginSecurityAuditContext,
): SecurityAuditFinding[] => {
  const findings: SecurityAuditFinding[] = [];

  const cfg = (ctx.config as {
    plugins?: { entries?: Record<string, { enabled?: boolean; config?: PluginConfig }> };
  }).plugins?.entries?.[PLUGIN_ID];

  const entry = cfg?.config ?? {};

  // Shadow mode is default and intentionally conservative. Surface a notice so
  // operators know enforcement is NOT active.
  if (!cfg?.enabled) {
    findings.push({
      checkId: `${PLUGIN_ID}.not-enabled`,
      severity: "info",
      title: "security-intercept is not enabled",
      detail:
        "The security-intercept plugin is installed but not enabled. Tool results are not inspected for prompt-injection or shell-injection.",
      remediation: `Set plugins.entries.${PLUGIN_ID}.enabled to true.`,
    });
    return findings;
  }

  if ((entry.mode ?? "shadow") === "shadow") {
    findings.push({
      checkId: `${PLUGIN_ID}.mode.shadow`,
      severity: "warn",
      title: "security-intercept is in shadow mode",
      detail:
        "Detections are emitted but interception actions are suppressed. Tool results matching a threat pattern still reach the LLM and the user.",
      remediation: `Once the detection rate is validated, set plugins.entries.${PLUGIN_ID}.config.mode to "enforce".`,
    });
  }

  if (entry.threats?.promptInjection === false) {
    findings.push({
      checkId: `${PLUGIN_ID}.threats.prompt-injection-off`,
      severity: "warn",
      title: "prompt-injection detection disabled",
      detail: "Tool results are not checked for prompt-injection payloads.",
      remediation: `Set plugins.entries.${PLUGIN_ID}.config.threats.promptInjection to true.`,
    });
  }
  if (entry.threats?.shellInjection === false) {
    findings.push({
      checkId: `${PLUGIN_ID}.threats.shell-injection-off`,
      severity: "warn",
      title: "shell-injection detection disabled",
      detail: "Tool results are not checked for destructive shell payloads.",
      remediation: `Set plugins.entries.${PLUGIN_ID}.config.threats.shellInjection to true.`,
    });
  }
  if (entry.threats?.credentialLeak === false) {
    findings.push({
      checkId: `${PLUGIN_ID}.threats.credential-leak-off`,
      severity: "warn",
      title: "credential-leak egress scan disabled",
      detail:
        "Outbound channel replies are not scanned for credential-shaped substrings. The memory-retrieval bypass path is unmonitored.",
      remediation: `Set plugins.entries.${PLUGIN_ID}.config.threats.credentialLeak to true.`,
    });
  }
  if (entry.threats?.piiExposure === false) {
    findings.push({
      checkId: `${PLUGIN_ID}.threats.pii-exposure-off`,
      severity: "warn",
      title: "pii-exposure egress scan disabled",
      detail: "Outbound channel replies are not scanned for PII substrings.",
      remediation: `Set plugins.entries.${PLUGIN_ID}.config.threats.piiExposure to true.`,
    });
  }
  if (entry.threats?.credentialLeakTool === false) {
    findings.push({
      checkId: `${PLUGIN_ID}.threats.credential-leak-tool-off`,
      severity: "warn",
      title: "credential-leak tool-origin detection disabled (Case 2)",
      detail: "Tool returns carrying credential material will not be annotated for LLM guidance.",
      remediation: `Set plugins.entries.${PLUGIN_ID}.config.threats.credentialLeakTool to true.`,
    });
  }
  if (entry.threats?.scopeExpansion === false) {
    findings.push({
      checkId: `${PLUGIN_ID}.threats.scope-expansion-off`,
      severity: "warn",
      title: "scope-expansion detection disabled (Case 2)",
      detail:
        "Tool returns attempting to expand agent scope/role will not be flagged and the next-tool approval gate will not fire.",
      remediation: `Set plugins.entries.${PLUGIN_ID}.config.threats.scopeExpansion to true.`,
    });
  }
  if (entry.case2?.approvalOnScopeExpansion === false) {
    findings.push({
      checkId: `${PLUGIN_ID}.case2.approval-off`,
      severity: "info",
      title: "scope-expansion approval gate disabled",
      detail:
        "After a scope-expansion detection, the next tool call proceeds without a user-approval prompt. This is a deliberate relaxation.",
      remediation: `Set plugins.entries.${PLUGIN_ID}.config.case2.approvalOnScopeExpansion to true to restore the gate.`,
    });
  }

  if (ctx.env?.OPENCLAW_SECURITY_OFF === "1") {
    findings.push({
      checkId: `${PLUGIN_ID}.kill-switch.env`,
      severity: "critical",
      title: "security-intercept kill switch is active",
      detail: "OPENCLAW_SECURITY_OFF=1 disables all detection and interception at runtime.",
      remediation: "Unset OPENCLAW_SECURITY_OFF once the incident that required the kill switch is resolved.",
    });
  }

  return findings;
};
