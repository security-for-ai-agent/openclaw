# security-intercept — Requirement Traceability

This document maps each clause of Zhangpeng Xie's original requirement to the
specific file, function, and hook that satisfies it.

## 1. Original requirement (verbatim)

> 原始需求：希望对LLM的输出进行检测，有异常时进行会话拦截，并且拦截后用户有感知
>
> 具体实现方案：在 after_tool_call hook 点进行检测，当检测到异常时，是否有合适的 hook 点支持拦截且修改模型提示词

Translation (working):

> **Original need:** detect anomalies in LLM-facing output; on anomaly, intercept
> the conversation; the user must perceive that the interception happened.
>
> **Proposed implementation:** detect at the `after_tool_call` hook; on detection,
> is there a suitable hook to support interception **and** modification of the
> model prompt?

### Clarifications from the 2026-04-20 voice call (`openclaw-security/discuss/notes-aemi.md`)

1. **Outer turn vs inner loop.** One user ask → one final reply is one *outer
   turn*. Inside it the agent may run multiple *inner loops* (LLM inference →
   tool dispatch → next inference). `runId` is stable across inner loops of one
   outer turn and resets across outer turns. Detection + interception must
   correlate by `runId`.
2. **Same-outer-turn notification.** The user must learn about an interception
   *in the current outer turn*, not on the next one — otherwise the attacker
   data may have already been exfiltrated by the time the next user message
   arrives.
3. **"LLM output" means the tool result that feeds the LLM.** `after_tool_call`
   is the canonical detection point.

## 2. Requirement-to-code traceability

Every clause below cites the file and symbol that carries its implementation.

### 2.1 检测 (Detect anomalies in tool-returned content that feeds the LLM)

| Sub-requirement | Implementation |
| --- | --- |
| Detection at `after_tool_call` hook | `src/hooks.ts` → `registerSecurityInterceptHooks` → the `after_tool_call` registration |
| Synchronous classifier (must complete before first `await` so `tool_result_persist` sees the flag in the same pipeline tick) | `src/detectors.ts` → `detect()` — pure-sync regex match |
| Default threat classes (Case 1a per `openclaw-security/discuss/plugin-design.md` §0) | `src/detectors.ts` → `DEFAULT_PROMPT_INJECTION_PATTERNS`, `DEFAULT_SHELL_INJECTION_PATTERNS` |
| Operator-extensible custom patterns | `openclaw.plugin.json` → `configSchema.properties.patterns`; `src/detectors.ts` → `compileDetectors()` |
| Per-class on/off switch | `openclaw.plugin.json` → `configSchema.properties.threats`; `src/detectors.ts` → `compileDetectors(..., enabled)` |
| State keyed by `runId` (stable within one outer turn) | `src/run-context.ts` → `SecurityRunState`, `byRun`, `recordDetection()` |

### 2.2 会话拦截 (Intercept the conversation)

Interception is two layers — content layer (what the LLM sees) and control
layer (what the LLM can do next) — and each layer branches by **Case** per
`src/detectors.ts:caseOf()` so Case 1a is strict and Case 2 is guided.

| Layer | Case | Hook | Implementation | Effect |
| --- | --- | --- | --- | --- |
| **Content** | **1a** | `tool_result_persist` (sync) | `src/hooks.ts` → `rewriteCase1aContent()` — replace with `[BLOCKED]` placeholder | LLM never sees the original threat content. |
| **Content** | **2** | `tool_result_persist` (sync) | `src/hooks.ts` → `rewriteCase2Content()` — prepend `[security-intercept: <class> — see security directive …]` and KEEP the original content | LLM sees the content plus a marker pointing at the directive it will receive next inner loop. |
| **Control** | **1a** | `before_tool_call` (async) | Hard `{ block: true, blockReason }` on any Case 1a detection in the run | Prevents workaround attempts in the same `runId`. |
| **Control** | **2 (`scope-expansion`)** | `before_tool_call` (async) | `{ requireApproval: { severity: "warning", timeoutBehavior: "deny" } }` | Next tool call is gated behind an explicit human approval prompt. Disabled via `case2.approvalOnScopeExpansion: false`. |
| **Control** | **2 (`credential-leak`, `oversized-result`)** | `before_tool_call` (async) | Returns `undefined` | No gate — these classes are informational and don't warrant blocking downstream tools. |
| **Precedence (mixed run)** | — | — | `src/hooks.ts` checks `state.detections.some(d => caseOf(d.class) === "1a")` first | Case 1a strictly supersedes Case 2 for the whole run: the run's strictest contract wins. |

### 2.3 修改模型提示词 (Modify the model prompt — Zhangpeng's open question)

**Answer:** yes, `before_prompt_build` is the async-awaited hook that takes
`prependContext` / `prependSystemContext` / `appendSystemContext` / `systemPrompt`.

| Sub-requirement | Case | Implementation |
| --- | --- | --- |
| Inject a **SECURITY ALERT** directive (strict: notify user, no retry, no more tools) | **1a** | `src/hooks.ts` → `before_prompt_build` branch `hasCase1a === true` path; reads `runId` from `PluginHookAgentContext` and returns `prependContext` + `appendSystemContext` |
| Inject a **SECURITY NOTE** directive per detected Case 2 class (keep content, guide reasoning, no reproduce / scope unchanged / summarize) | **2** | `src/hooks.ts` → `before_prompt_build` branch `hasCase1a === false` path; merges per-class directives from `src/directives.ts:directiveFor()`, de-duplicated by class so repeated hits don't blow the prompt |
| Per-class directive text | **2** | `src/directives.ts` — one entry per class: `credential-leak` (don't reproduce verbatim), `scope-expansion` (role unchanged, next tool needs approval), `oversized-result` (summarize, don't quote) |

### 2.4 用户感知 (User perceives the interception, same outer turn)

Four delivery paths, all guaranteed in the current outer turn:

| Path | Mechanism |
| --- | --- |
| **LLM-driven text reply** | `before_prompt_build` tells the LLM to announce the block. `before_tool_call` blocks any follow-on tool call, forcing the LLM into natural-language response in the same outer turn. |
| **Transcript marker for the user-visible channel that renders tool results** | `tool_result_persist` replacement inserts a `[BLOCKED by security-intercept] …` placeholder which replaces the raw tool output in the session. |
| **Outbound reply redaction / cancel (Case 1b)** | `message_sending` scans the final channel-bound reply and either (a) replaces matched substrings with `[REDACTED:<kind>]` + an inline security notice, or (b) cancels the whole message and substitutes a short notice when `criticalHit` (private-key PEM) or `egress.action=cancel` is set. |
| **Silent-LLM safety signal** | `before_agent_reply` (v1: observational — logs a warning if the reply body does not mention the block; v2 follow-on: synthesize a reply-tail; see §4 below). |

### 2.4b Memory-retrieval bypass coverage (Case 1b)

Per `openclaw-security/discuss/notes-aemi.md`, a user can install the plugin
*after* storing sensitive data, then have that data surfaced via a memory
retrieval that does not hit any tool or LLM hook. `message_sending` is the
only chokepoint before the channel delivers the reply. The Case 1b path is
independent of `runId` correlation — it pattern-matches the raw
`event.content` against egress rules compiled by
`src/egress-scan.ts:compileEgressRules()`.

| Sub-requirement | Implementation |
| --- | --- |
| Detect credential-shape substrings in outbound content | `src/egress-scan.ts` → `DEFAULT_CREDENTIAL_RULES` (AWS, OpenAI-like, GitHub PAT, bearer, password-assignment, PEM private key) |
| Detect PII in outbound content | `src/egress-scan.ts` → `DEFAULT_PII_RULES` (US SSN, email, candidate credit-card digits) |
| Redact matched substrings in place | `src/egress-scan.ts` → `scanEgress()` with `severity: "soft"` rules; `src/hooks.ts` message_sending returns `{ content: redacted + notice }` |
| Cancel the whole message on a "hard" hit (private-key PEM) | `src/egress-scan.ts` reports `criticalHit: true`; hook returns `{ cancel: true, content: "[security-intercept: message cancelled] …" }` |
| Per-class enable / disable and custom extra patterns | `openclaw.plugin.json` → `threats.credentialLeak`, `threats.piiExposure`, `patterns.credentialLeak`, `patterns.piiExposure`; wired through `compileEgressRules()` |
| Operator choice between per-substring redaction and whole-message cancel | `openclaw.plugin.json` → `egress.action` (`redact` default, `cancel` alternative) |
| User-visible notice on soft redaction | `openclaw.plugin.json` → `egress.addNotice` (default true); hook appends the notice after the redacted body |

### 2.5 审计 (Audit / operator visibility)

| Requirement | Implementation |
| --- | --- |
| Structured finding available to `openclaw security audit` and `openclaw doctor` | `src/audit.ts` → `securityInterceptAuditCollector` (registered via `securityAuditCollectors` on `definePluginEntry` in `index.ts`) |
| Runtime log line on every detection | `src/hooks.ts` → `api.logger.warn` in the `after_tool_call` registration |

## 3. Operational invariants

| Invariant | Where enforced |
| --- | --- |
| Kill switch: `OPENCLAW_SECURITY_OFF=1` disables all detection and interception | `src/hooks.ts` → `killSwitchActive()`, checked at the top of every hook |
| Shadow mode is the default (record + audit, never modify) | `src/hooks.ts` → `mode() === "shadow"` short-circuits `tool_result_persist`, `before_prompt_build`, `before_tool_call` |
| State cleanup on `session_end` | `src/hooks.ts` → the `session_end` registration → `dropSession()` |
| Cross-`runId` isolation | `src/run-context.ts` — all state keyed by `runId`; `hasAnyDetection()` / `getStateByRun()` reject foreign `runId` |
| Sync-before-await detection ordering | `src/hooks.ts` — `detect()` and `recordDetection()` complete synchronously; any async work lands after the mark. Test: `index.test.ts` → "sync-before-await invariant" |

## 4. Known limitations (tracked for v2)

- **`before_agent_reply` is observational in v1.** The plugin logs a warning if
  the LLM's reply body does not mention the block, but does not synthesize a
  reply-tail directly. A v2 iteration can use `ReplyPayload` synthesis to
  guarantee user-visible notification even when the LLM stays silent.
- **`message_sending` does not correlate to `runId` for Case 1a's safety-net role.**
  `PluginHookMessageContext` (channelId / accountId / conversationId) carries no
  `runId` or `sessionKey`, so a Case 1a detection cannot be matched back to the
  outbound reply it produced. `before_agent_reply` (which does carry `runId`)
  is used for that instead. Case 1b does NOT need this correlation because it
  pattern-matches the reply content directly — that is why it can run from
  `message_sending` even when no `runId`-keyed state exists.
- **Async-split classifier path is not implemented.** Case 2 detection today is
  regex-only per the same sync-before-await constraint as Case 1a. An external
  classifier (secret scanner, LLM-as-judge) would use the async-split pattern
  documented in `hardening-combo-prompt-modify.md §7` — tool_result_persist
  stashes a placeholder, before_prompt_build runs the async classifier. Still
  deferred.

## 5. Test coverage mapping

| Test file | Covers |
| --- | --- |
| `src/detectors.test.ts` | §2.1 — detector regex set (Case 1a + Case 2), `caseOf()` routing, custom-pattern merging, invalid-regex safety, negative cases, first-match precedence, ordering across cases |
| `src/egress-scan.test.ts` | §2.4b — credential + PII egress rules, in-place redaction, critical-hit detection, multi-class simultaneous hits |
| `src/run-context.test.ts` | §2.1 / §3 — shared-state lifecycle, `runId` isolation, `session_end` cleanup, tool-call-id indexing |
| `index.test.ts` | §2.2 / §2.3 / §2.4 / §2.4b / §3 — full hook chain through a mock `api`: Case 1a enforce vs shadow vs kill-switch, Case 1b message_sending redact/cancel/notice paths, Case 2 annotate-not-replace + per-class directive + scope-expansion approval gate + Case 1a precedence over Case 2 + oversized-threshold override, cross-run isolation, sync-before-await invariant, `session_end` cleanup |

## 6. Requirement coverage summary

| Zhangpeng's requirement | Satisfied? | Hook / file |
| --- | --- | --- |
| 检测 at `after_tool_call` | ✅ | `after_tool_call` → `src/hooks.ts`, `src/detectors.ts` |
| 会话拦截 (content layer) | ✅ | `tool_result_persist` → `src/hooks.ts` |
| 会话拦截 (control layer, same outer turn) | ✅ | `before_tool_call` → `src/hooks.ts` |
| 修改模型提示词 | ✅ | `before_prompt_build` → `src/hooks.ts` |
| 用户感知 (same outer turn, LLM-driven) | ✅ | `before_prompt_build` directive + `before_tool_call` forces text-only reply |
| 用户感知 (safety net when LLM stays silent) | Partial — v1 observational | `before_agent_reply` → `src/hooks.ts` |
| 审计 | ✅ | `registerSecurityAuditCollector` → `src/audit.ts` |
| 可降级 (shadow mode + kill switch) | ✅ | `src/hooks.ts`, `openclaw.plugin.json` |
| 内存检索绕过 (Case 1b) | ✅ | `message_sending` → `src/hooks.ts`, `src/egress-scan.ts` |
| 保留内容 + 指导模型 (Case 2 — credential-leak / scope-expansion / oversized-result) | ✅ | `src/hooks.ts` (per-case branches) + `src/directives.ts` (class-specific wording) + `src/detectors.ts` (`caseOf`, new class detectors) |
| 人工审批 on scope-expansion (Case 2) | ✅ | `src/hooks.ts` `before_tool_call` `{ requireApproval: … }` branch |

## 7. Source material traceability

The design leans on — and is verifiable against — the following sibling docs
under `openclaw-security/discuss/`:

- `group-discuss-1.md` — original 2026-04-09 → 2026-04-20 Feishu chat; source of the 1a/1b/2 case plan and the same-outer-turn correction (Zhangpeng 04-20 00:43).
- `notes-aemi.md` — 2026-04-20 voice-call AI notes; source of the outer-vs-inner-turn `runId` clarification and the memory-retrieval bypass scenario.
- `hardening-hook-combinations.md` — general analysis; source of the "shared-state bridge keyed by `runId`" pattern and the sync-before-await invariant.
- `hardening-combo-intercept.md` — Case 1a mechanism in detail; this plugin is a direct implementation of that combo with the same-outer-turn correction applied.
- `openclaw-security-plugin.md` — OpenClaw's plugin-authoring contract (the hooks listed here, `registerSecurityAuditCollector`, the `definePluginEntry` entry shape); every hook and API used by this plugin is documented there.
- `plugin-design.md` — the unified plugin architecture; this PR covers §0 Case 1a only, leaving 1b and Case 2 as follow-on work.
