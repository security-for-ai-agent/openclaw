# content-scanner — Requirement Traceability (core implementation)

Core-owned successor to `extensions/security-intercept/`. Same three-case
contract as the plugin, but implemented as a built-in module under
`src/security/content-scanner/` and invoked directly by the agent runtime
alongside the plugin hook runner. Cannot be loaded/unloaded by an operator
mis-configuration; runs on every tool result and every outbound reply unless
the kill switch or `mode: "off"` is set.

## 1. Captured requirement

From the design-discussion corpus under `openclaw-security/discuss/`
(`group-discuss-1.md`, 2026-04-09 → 2026-04-20) and the 2026-04-20 voice-call
follow-up (`notes-aemi.md`). Paraphrased:

- Detect anomalous content in the material that feeds the agent and the
  material that the agent sends out.
- On detection, intercept the ongoing turn so the offending content does not
  reach the LLM or the user.
- Notify the user within the same outer turn — not on the next one — so an
  attacker cannot exfiltrate before the user sees the block.
- Support content-replacing interception (strict) and content-preserving
  prompt-modify guidance (soft) depending on the class of the threat.

## 2. Core concepts

- **Outer turn** — one user ask → one final reply the user sees. One outer
  turn spans one or more inner LLM loops.
- **runId** — stable across inner loops of a single outer turn; resets across
  outer turns. Scanner state is keyed here.
- **Case 1a** — strict intercept: replace tool-result content, hard-block
  follow-on tools.
- **Case 1b** — egress intercept: redact / cancel outbound channel replies
  that carry credential or PII shapes, regardless of whether a tool or LLM
  hook fired.
- **Case 2** — prompt-modify: keep the tool result visible, inject a
  class-specific LLM directive, optionally gate the next tool call behind
  human approval (`scope-expansion`).
- **Precedence** — when a run has both Case 1a and Case 2 detections, Case 1a
  wins: the strictest contract per run is the contract the user sees.

## 3. Requirement → code traceability

### 3.1 Detection on the path that feeds the LLM (`after_tool_call`)

| Sub-requirement | Implementation |
| --- | --- |
| Sync detection at the same tick as `after_tool_call` so the flag is visible to the sync `tool_result_persist` | `src/agents/pi-embedded-subscribe.handlers.tools.ts` → `handleToolExecutionEnd` — inserts `getContentScanner().onAfterToolCall(...)` right after `sanitizedResult` is computed and before any `await` |
| Pure-regex classifier (no network, no async) | `src/security/content-scanner/detectors.ts` → `detect()` |
| Default threat classes | `DEFAULT_PROMPT_INJECTION_PATTERNS` (Case 1a), `DEFAULT_SHELL_INJECTION_PATTERNS` (Case 1a), `DEFAULT_CREDENTIAL_LEAK_PATTERNS` (Case 2), `DEFAULT_SCOPE_EXPANSION_PATTERNS` (Case 2), oversized-threshold (Case 2) |
| Operator-extensible custom patterns | `ContentScannerConfig.patterns.*`; `compileDetectors()` in `detectors.ts` |
| Per-class enable / disable | `ContentScannerConfig.threats.*`; `compileDetectors(..., enabled)` |
| Run-scoped state keyed by `runId` | `src/security/content-scanner/run-context.ts` → `ContentScannerRunContext`; secondary `toolCallId → runId` index for the sync `tool_result_persist` dispatch that carries no `runId` |

### 3.2 Content-layer interception (sync `tool_result_persist`)

| Case | Implementation |
| --- | --- |
| **1a** — replace with `[BLOCKED by content-scanner] …` | `src/security/content-scanner/scanner.ts` → `rewriteCase1aContent()` |
| **2** — prepend `[content-scanner: <class> — see security directive …]`, keep original content | `src/security/content-scanner/scanner.ts` → `rewriteCase2Content()` |
| Splice into core | `src/agents/session-tool-result-guard-wrapper.ts` → `guardSessionManager` — scanner runs first; if it rewrites, the plugin `tool_result_persist` hook sees the rewritten message |

### 3.3 LLM-guidance layer (`before_prompt_build`)

| Case | Implementation |
| --- | --- |
| **1a** — strict SECURITY ALERT (notify user, do not retry, do not call more tools) | `src/security/content-scanner/scanner.ts` → `ContentScanner.onBeforePromptBuild` branch `hasCase1a === true` |
| **2** — per-class SECURITY NOTE from the directive table | `src/security/content-scanner/scanner.ts` → `ContentScanner.onBeforePromptBuild` branch `hasCase1a === false` → `directiveFor()` |
| Per-class directive text | `src/security/content-scanner/directives.ts` — `credential-leak`, `scope-expansion`, `oversized-result` |
| Splice into core | `src/agents/pi-embedded-runner/run/attempt.prompt-helpers.ts` → `resolvePromptBuildHookResult` — scanner runs in parallel with the plugin hook; `prependContext` and `appendSystemContext` are merged with scanner-first ordering |

### 3.4 Control-layer interception (`before_tool_call`)

| Case | Implementation |
| --- | --- |
| **1a** — hard `block: true` + `blockReason` | `src/security/content-scanner/scanner.ts` → `ContentScanner.onBeforeToolCall` branch `hasCase1a === true` |
| **2 scope-expansion** — `requireApproval` with `severity: "warning"`, `timeoutBehavior: "deny"` | Same function; `hasScopeExpansion && approvalOnScopeExpansion()` branch |
| **2 other** — pass through (no gate) | Same function; returns `undefined` |
| Splice into core | `src/agents/pi-tools.before-tool-call.ts` — scanner runs FIRST; a scanner block/approval is terminal and skips the plugin hook runner |

### 3.5 Outbound layer (Case 1b — `message_sending`)

| Sub-requirement | Implementation |
| --- | --- |
| Scan every channel-bound reply for credential / PII shapes even when no tool/LLM hook fired (memory-retrieval / cached-reply bypass) | `src/security/content-scanner/egress-scan.ts` → `compileEgressRules()`, `scanEgress()` |
| Soft hits redact in place and append a security notice | Rules with `severity: "soft"`; `scanner.ts` → `onMessageSending` branches with `scan.criticalHit === false` |
| Critical hits (private-key PEM blocks) cancel the whole message | Rules with `severity: "hard"`; `scanner.ts` → `onMessageSending` branch with `scan.criticalHit === true` |
| Operator can force hard-cancel on every hit | `ContentScannerConfig.egress.action = "cancel"` |
| Operator can suppress the redaction notice | `ContentScannerConfig.egress.addNotice = false` |
| Splice into core | `src/infra/outbound/deliver.ts` → `applyMessageSendingHook` — scanner runs BEFORE the plugin hook runner AND regardless of whether any plugin registered `message_sending` (since Case 1b must always fire) |

### 3.6 Same-outer-turn user notification

| Delivery path | Implementation |
| --- | --- |
| LLM-driven reply | `before_prompt_build` directive + hard-block on further tool calls → LLM emits text that acknowledges the block in the same outer turn |
| Transcript marker | `tool_result_persist` replacement inserts `[BLOCKED by content-scanner] …` visible in channels that render tool results |
| Outbound redaction / cancel notice | `message_sending` returns either the cancel reply or the redacted reply + appended security notice |

### 3.7 Session cleanup

| Sub-requirement | Implementation |
| --- | --- |
| Drop run state when a session ends | `src/gateway/session-reset-service.ts` → `emitGatewaySessionEndPluginHook` invokes `getContentScanner().onSessionEnd(...)` alongside the plugin `session_end` dispatch |
| State cleanup keyed by `sessionKey` and `sessionId` | `src/security/content-scanner/run-context.ts` → `dropSession()` |

### 3.8 Audit

| Sub-requirement | Implementation |
| --- | --- |
| Findings surface in `openclaw security audit` / `openclaw doctor` | `src/security/audit.ts` → `runSecurityAudit` — `getContentScanner().collectAuditFindings(env)` is pushed onto the core report alongside other non-deep collectors |
| Kill-switch active → critical finding | `scanner.ts` → `collectAuditFindings` branch `env.OPENCLAW_SECURITY_OFF === "1"` |
| `mode: "off"` → info finding | Same function; `mode() === "off"` branch |
| `mode: "shadow"` → warn finding | Same function; `mode() === "shadow"` branch |
| Per-threat off → warn finding | Same function; `threats.<class> === false` branches |

### 3.9 Operational invariants

| Invariant | Enforcement |
| --- | --- |
| Sync-before-await ordering between detect and persist | `scanner.ts` → `onAfterToolCall` is sync (no awaits inside the body after the flag is recorded); call sites invoke it synchronously |
| Kill switch via `OPENCLAW_SECURITY_OFF=1` | `scanner.ts` → `killSwitchActive()` checked at the top of `isActive()`; every entry point gates on `isActive()` first |
| Shadow mode (record, do not mutate) is safe default | `mode: "off"` is the default when no config is applied; `mode: "shadow"` records detections but skips every transcript / prompt / tool / egress mutation |
| Run isolation | `ContentScannerRunContext.byRun` keyed by `runId`; `getStateByRun(unknownRun)` returns `undefined` |
| Plugin hooks still work unchanged | All six splices run the plugin hook runner in addition to the scanner; the scanner's result becomes the plugin hook's starting point where it makes sense (`tool_result_persist`, `message_sending`) or merges alongside (`before_prompt_build`) |

## 4. Known limitations (v2 follow-ups)

- **`OpenClawConfig.security.contentScanner` zod schema not yet wired.** The
  scanner accepts config via its constructor and `reconfigureContentScanner()`,
  but the gateway bootstrap does not yet call those functions from an
  operator-facing `security.contentScanner` config block. Until that wiring
  lands, the scanner defaults to `mode: "off"` on a fresh gateway start.
  Follow-up PR is a pure plumbing change with no behavior drift.
- **Same-outer-turn notification depends on the LLM acknowledging the block.**
  If the LLM is stuck in a blocked tool loop and emits no text, the user
  reply for that turn may omit the block notice. `message_sending` Case 1b
  covers the user-visible path for egress hits, but the Case 1a LLM-silent
  edge case is still observational. A `before_agent_reply` synthesis path is
  the v2 option, mirroring the plugin's `REQUIREMENTS.md §4` entry.
- **Async classifier path not implemented.** Detection today is regex-only
  per the same sync-before-await constraint as the plugin. The async-split
  pattern from `hardening-combo-prompt-modify.md §7` is available as a
  future option.

## 5. Test coverage mapping

| Test file | Covers |
| --- | --- |
| `src/security/content-scanner/detectors.test.ts` | §3.1 — detector regex set (1a + 2), `caseOf()` routing, custom-pattern merging, invalid-regex safety, negative cases, first-match precedence, Case 1a beats Case 2 |
| `src/security/content-scanner/egress-scan.test.ts` | §3.5 — credential + PII egress rules, in-place redaction, critical-hit detection, per-class enable flags |
| `src/security/content-scanner/run-context.test.ts` | §3.1 / §3.7 — shared-state lifecycle, `runId` isolation, `session_end` cleanup, tool-call-id indexing |
| `src/security/content-scanner/scanner.test.ts` | §3.2 / §3.3 / §3.4 / §3.5 / §3.6 / §3.7 / §3.8 / §3.9 — full scanner pipeline driven through its public entry points: Case 1a enforce, Case 2 annotate + per-class directive + scope-expansion approval, Case 1b redact / cancel / notice, Case 1a precedence over Case 2, shadow mode, kill switch, audit findings, reconfigure at runtime |

## 6. Divergences from the plugin implementation

This module is a parallel implementation of `extensions/security-intercept/`
with the following intentional differences:

| Plugin version | Core version |
| --- | --- |
| Loaded via `definePluginEntry(...)` under `extensions/` | Loaded as a core singleton at `src/security/content-scanner/` |
| Registers via `api.on("after_tool_call", ...)` etc. | Core call sites invoke `getContentScanner().onAfterToolCall(...)` directly; plugin hook runner runs in addition |
| Config lives under `plugins.entries.security-intercept.config` | Config intended to live under `security.contentScanner` (wiring follow-up; see §4) |
| Disabled by default (`enabledByDefault: false`) | Defaults to `mode: "off"` at the module level; operators opt in by setting `mode: "shadow"` or `"enforce"` |
| Cannot be removed without touching the plugin registry | Cannot be removed by any operator action short of a code change + rebuild |
| Audit findings flow through `registerSecurityAuditCollector` | Audit findings flow directly into `runSecurityAudit` via `collectAuditFindings()` |

## 7. Requirement coverage summary

| Requirement | Satisfied | Primary site |
| --- | --- | --- |
| Detect in tool output | ✅ | `handleToolExecutionEnd` → `ContentScanner.onAfterToolCall` |
| Replace malicious tool result (Case 1a) | ✅ | `guardSessionManager` → `ContentScanner.onToolResultPersist` |
| Annotate + keep risky content (Case 2) | ✅ | Same site, `caseOf()` branch |
| Modify LLM prompt for next inner loop | ✅ | `resolvePromptBuildHookResult` → `ContentScanner.onBeforePromptBuild` |
| Block follow-on tools (Case 1a) | ✅ | `dispatchBeforeToolCallHook` → `ContentScanner.onBeforeToolCall` |
| Require approval on scope-expansion (Case 2) | ✅ | Same site, requireApproval branch |
| Outbound redact / cancel for LLM-bypass paths (Case 1b) | ✅ | `applyMessageSendingHook` → `ContentScanner.onMessageSending` |
| User perceives the block this outer turn | ✅ | LLM-driven + transcript marker + outbound notice |
| Audit / operator visibility | ✅ | `runSecurityAudit` → `ContentScanner.collectAuditFindings` |
| Kill switch + shadow mode | ✅ | `ContentScanner.isActive()` + mode gating at every entry point |
| Session cleanup | ✅ | `emitGatewaySessionEndPluginHook` → `ContentScanner.onSessionEnd` |

## 8. Source material

- `openclaw-security/discuss/group-discuss-1.md` — original design thread.
- `openclaw-security/discuss/notes-aemi.md` — 2026-04-20 voice-call notes that
  established the outer-vs-inner-turn `runId` semantics and introduced the
  memory-retrieval bypass scenario.
- `openclaw-security/discuss/hardening-hook-combinations.md` — analysis of
  why no single hook is sufficient; defines the shared-state-bridge pattern.
- `openclaw-security/discuss/hardening-combo-intercept.md` — Case 1a mechanism
  in detail.
- `openclaw-security/discuss/hardening-combo-prompt-modify.md` — Case 2
  mechanism in detail.
- `openclaw-security/discuss/plugin-design.md` — unified three-case plugin
  architecture (the immediate parent of this design).
- `openclaw-security/discuss/openclaw-security-design.md` — inventory of
  OpenClaw's existing security surfaces (boundary-based, not model-robustness).
