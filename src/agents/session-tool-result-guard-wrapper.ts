import type { AgentMessage } from "@mariozechner/pi-agent-core";
import type { SessionManager } from "@mariozechner/pi-coding-agent";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import { getGlobalHookRunner } from "../plugins/hook-runner-global.js";
import { getContentScanner } from "../security/content-scanner/index.js";
import {
  applyInputProvenanceToUserMessage,
  type InputProvenance,
} from "../sessions/input-provenance.js";
import { resolveLiveToolResultMaxChars } from "./pi-embedded-runner/tool-result-truncation.js";
import { installSessionToolResultGuard } from "./session-tool-result-guard.js";

export type GuardedSessionManager = SessionManager & {
  /** Flush any synthetic tool results for pending tool calls. Idempotent. */
  flushPendingToolResults?: () => void;
  /** Clear pending tool calls without persisting synthetic tool results. Idempotent. */
  clearPendingToolResults?: () => void;
};

/**
 * Apply the tool-result guard to a SessionManager exactly once and expose
 * a flush method on the instance for easy teardown handling.
 */
export function guardSessionManager(
  sessionManager: SessionManager,
  opts?: {
    agentId?: string;
    sessionKey?: string;
    config?: OpenClawConfig;
    contextWindowTokens?: number;
    inputProvenance?: InputProvenance;
    allowSyntheticToolResults?: boolean;
    allowedToolNames?: Iterable<string>;
  },
): GuardedSessionManager {
  if (typeof (sessionManager as GuardedSessionManager).flushPendingToolResults === "function") {
    return sessionManager as GuardedSessionManager;
  }

  const hookRunner = getGlobalHookRunner();
  const beforeMessageWrite = hookRunner?.hasHooks("before_message_write")
    ? (event: { message: import("@mariozechner/pi-agent-core").AgentMessage }) => {
        return hookRunner.runBeforeMessageWrite(event, {
          agentId: opts?.agentId,
          sessionKey: opts?.sessionKey,
        });
      }
    : undefined;

  const hookRunnerHasToolResultPersist = hookRunner?.hasHooks("tool_result_persist") ?? false;
  const scanner = getContentScanner();
  const transform =
    hookRunnerHasToolResultPersist || scanner.isActive()
      ? (
          message: AgentMessage,
          meta: { toolCallId?: string; toolName?: string; isSynthetic?: boolean },
        ) => {
          // Core content scanner runs first. If it rewrites the message, the
          // plugin hook then sees the already-rewritten content; if the scanner
          // stays silent, the plugin hook operates on the original.
          let current = message;
          try {
            const scanned = scanner.onToolResultPersist({
              toolCallId: meta.toolCallId,
              message: current,
            });
            if (scanned?.message) current = scanned.message;
          } catch {
            // Never let scanner failure block transcript writes.
          }
          if (!hookRunnerHasToolResultPersist || !hookRunner) return current;
          const out = hookRunner.runToolResultPersist(
            {
              toolName: meta.toolName,
              toolCallId: meta.toolCallId,
              message: current,
              isSynthetic: meta.isSynthetic,
            },
            {
              agentId: opts?.agentId,
              sessionKey: opts?.sessionKey,
              toolName: meta.toolName,
              toolCallId: meta.toolCallId,
            },
          );
          return out?.message ?? current;
        }
      : undefined;

  const guard = installSessionToolResultGuard(sessionManager, {
    sessionKey: opts?.sessionKey,
    transformMessageForPersistence: (message) =>
      applyInputProvenanceToUserMessage(message, opts?.inputProvenance),
    transformToolResultForPersistence: transform,
    allowSyntheticToolResults: opts?.allowSyntheticToolResults,
    allowedToolNames: opts?.allowedToolNames,
    beforeMessageWriteHook: beforeMessageWrite,
    maxToolResultChars:
      typeof opts?.contextWindowTokens === "number"
        ? resolveLiveToolResultMaxChars({
            contextWindowTokens: opts.contextWindowTokens,
            cfg: opts.config,
            agentId: opts.agentId,
          })
        : undefined,
  });
  (sessionManager as GuardedSessionManager).flushPendingToolResults = guard.flushPendingToolResults;
  (sessionManager as GuardedSessionManager).clearPendingToolResults = guard.clearPendingToolResults;
  return sessionManager as GuardedSessionManager;
}
