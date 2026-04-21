// Shared state bridging the four in-run hooks of Case 1a.
//
// Keyed primarily by `runId` (stable across inner loops of one outer turn per
// the 2026-04-20 voice-call clarification in notes-aemi.md). `tool_result_persist`
// does not receive `runId` in its context — only `toolCallId` — so we maintain a
// secondary `toolCallId → runId` index.

import type { Detection } from "./detectors.js";

export type SecurityRunState = {
  runId: string;
  sessionKey?: string;
  sessionId?: string;
  detections: Detection[];
  interceptedToolCallIds: Set<string>;
};

const byRun = new Map<string, SecurityRunState>();
const toolCallToRun = new Map<string, string>();

export function ensureRunState(
  runId: string,
  sessionKey?: string,
  sessionId?: string,
): SecurityRunState {
  let state = byRun.get(runId);
  if (!state) {
    state = {
      runId,
      sessionKey,
      sessionId,
      detections: [],
      interceptedToolCallIds: new Set(),
    };
    byRun.set(runId, state);
  }
  return state;
}

export function recordDetection(runId: string, detection: Detection): void {
  const state = ensureRunState(runId);
  state.detections.push(detection);
  if (detection.toolCallId) {
    state.interceptedToolCallIds.add(detection.toolCallId);
    toolCallToRun.set(detection.toolCallId, runId);
  }
}

export function getStateByRun(runId: string | undefined): SecurityRunState | undefined {
  if (!runId) return undefined;
  return byRun.get(runId);
}

export function getDetectionByToolCallId(toolCallId: string | undefined): Detection | undefined {
  if (!toolCallId) return undefined;
  const runId = toolCallToRun.get(toolCallId);
  if (!runId) return undefined;
  const state = byRun.get(runId);
  if (!state) return undefined;
  return state.detections.find((d) => d.toolCallId === toolCallId);
}

export function hasAnyDetection(runId: string | undefined): boolean {
  if (!runId) return false;
  const state = byRun.get(runId);
  return !!state && state.detections.length > 0;
}

/** Drop everything keyed off a runId (called on session_end). */
export function dropRun(runId: string | undefined): void {
  if (!runId) return;
  const state = byRun.get(runId);
  if (state) {
    for (const id of state.interceptedToolCallIds) toolCallToRun.delete(id);
  }
  byRun.delete(runId);
}

/** Drop every run belonging to a session. */
export function dropSession(sessionKey: string | undefined, sessionId?: string): void {
  if (!sessionKey && !sessionId) return;
  for (const [runId, state] of byRun) {
    if (
      (sessionKey && state.sessionKey === sessionKey) ||
      (sessionId && state.sessionId === sessionId)
    ) {
      for (const id of state.interceptedToolCallIds) toolCallToRun.delete(id);
      byRun.delete(runId);
    }
  }
}

/** Test-only. */
export function __resetForTests(): void {
  byRun.clear();
  toolCallToRun.clear();
}

/** Test-only: inspect run count. */
export function __runCount(): number {
  return byRun.size;
}
