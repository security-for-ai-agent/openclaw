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
layer (what the LLM can do next).

| Layer | Hook | Implementation | Effect |
| --- | --- | --- | --- |
| **Content** — replace tool result with `[BLOCKED]` placeholder | `tool_result_persist` (sync) | `src/hooks.ts` → the `tool_result_persist` registration; correlates via `toolCallId` since `PluginHookToolResultPersistContext` carries no `runId` | LLM never sees the original threat content. |
| **Control** — block any further tool call in this outer turn | `before_tool_call` (async) | `src/hooks.ts` → the `before_tool_call` registration; checks `hasAnyDetection(ctx.runId)`; returns `{ block: true, blockReason }` | Prevents follow-up workaround attempts in the same `runId`. |

### 2.3 修改模型提示词 (Modify the model prompt — Zhangpeng's open question)

**Answer:** yes, `before_prompt_build` is the async-awaited hook that takes
`prependContext` / `prependSystemContext` / `appendSystemContext` / `systemPrompt`.

| Sub-requirement | Implementation |
| --- | --- |
| Inject a SECURITY ALERT directive into the next inner LLM loop (same `runId`, same outer turn) | `src/hooks.ts` → the `before_prompt_build` registration; reads `runId` from `PluginHookAgentContext` and returns a result with `prependContext` + `appendSystemContext` |
| Instruct the LLM to tell the user, not retry, not reconstruct, not call more tools | Directive text inside the same registration (items 1–4 of the numbered list) |

### 2.4 用户感知 (User perceives the interception, same outer turn)

Three delivery paths, all guaranteed in the current outer turn:

| Path | Mechanism |
| --- | --- |
| **LLM-driven text reply** | `before_prompt_build` tells the LLM to announce the block. `before_tool_call` blocks any follow-on tool call, forcing the LLM into natural-language response in the same outer turn. |
| **Transcript marker for the user-visible channel that renders tool results** | `tool_result_persist` replacement inserts a `[BLOCKED by security-intercept] …` placeholder which replaces the raw tool output in the session. |
| **Silent-LLM safety signal** | `before_agent_reply` (v1: observational — logs a warning if the reply body does not mention the block; v2 follow-on: synthesize a reply-tail; see §4 below). |

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
- **`message_sending` is not used as a safety net.** `PluginHookMessageContext`
  (channelId / accountId / conversationId) carries no `runId` or `sessionKey`,
  so we cannot correlate an outbound channel reply back to a run's detections.
  `before_agent_reply` (which does carry `runId`) is used instead. Resolving
  this properly is part of the memory-retrieval-bypass work item Rugang owes
  Zhangpeng (see `openclaw-security/discuss/notes-aemi.md` action item).
- **Case 1b (memory-retrieval bypass) is not implemented.** The scope of this
  PR is Case 1a only, per Rugang's 2026-04-20 00:35 plan in
  `openclaw-security/discuss/group-discuss-1.md`. Case 1b ships in a later PR
  once the output-point interception question is answered.
- **Case 2 (prompt-modify combo) is not implemented.** Deferred to a follow-on
  PR per the same plan.

## 5. Test coverage mapping

| Test file | Covers |
| --- | --- |
| `src/detectors.test.ts` | §2.1 — detector regex set, custom-pattern merging, invalid-regex safety, negative cases, first-match precedence |
| `src/run-context.test.ts` | §2.1 / §3 — shared-state lifecycle, `runId` isolation, `session_end` cleanup, tool-call-id indexing |
| `index.test.ts` | §2.2 / §2.3 / §2.4 / §3 — full hook chain through a mock `api`: enforce vs shadow vs kill-switch, cross-run isolation, sync-before-await invariant, `session_end` cleanup |

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

## 7. Source material traceability

The design leans on — and is verifiable against — the following sibling docs
under `openclaw-security/discuss/`:

- `group-discuss-1.md` — original 2026-04-09 → 2026-04-20 Feishu chat; source of the 1a/1b/2 case plan and the same-outer-turn correction (Zhangpeng 04-20 00:43).
- `notes-aemi.md` — 2026-04-20 voice-call AI notes; source of the outer-vs-inner-turn `runId` clarification and the memory-retrieval bypass scenario.
- `hardening-hook-combinations.md` — general analysis; source of the "shared-state bridge keyed by `runId`" pattern and the sync-before-await invariant.
- `hardening-combo-intercept.md` — Case 1a mechanism in detail; this plugin is a direct implementation of that combo with the same-outer-turn correction applied.
- `openclaw-security-plugin.md` — OpenClaw's plugin-authoring contract (the hooks listed here, `registerSecurityAuditCollector`, the `definePluginEntry` entry shape); every hook and API used by this plugin is documented there.
- `plugin-design.md` — the unified plugin architecture; this PR covers §0 Case 1a only, leaving 1b and Case 2 as follow-on work.
