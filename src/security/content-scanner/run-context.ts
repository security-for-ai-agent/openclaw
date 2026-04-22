// Run-scoped scanner state — the shared-state bridge between the Case 1a hooks.
//
// Keyed primarily by `runId` (stable across inner LLM loops of one outer turn;
// resets across outer turns). The sync `tool_result_persist` dispatch does not
// receive `runId` in its context, so we also maintain a secondary
// `toolCallId -> runId` index.

import type { Detection } from "./detectors.js";

export type SecurityRunState = {
  runId: string;
  sessionKey?: string;
  sessionId?: string;
  detections: Detection[];
  interceptedToolCallIds: Set<string>;
};

export class ContentScannerRunContext {
  private readonly byRun = new Map<string, SecurityRunState>();
  private readonly toolCallToRun = new Map<string, string>();

  ensureRun(runId: string, sessionKey?: string, sessionId?: string): SecurityRunState {
    let state = this.byRun.get(runId);
    if (!state) {
      state = {
        runId,
        sessionKey,
        sessionId,
        detections: [],
        interceptedToolCallIds: new Set(),
      };
      this.byRun.set(runId, state);
    }
    return state;
  }

  recordDetection(runId: string, detection: Detection): void {
    const state = this.ensureRun(runId);
    state.detections.push(detection);
    if (detection.toolCallId) {
      state.interceptedToolCallIds.add(detection.toolCallId);
      this.toolCallToRun.set(detection.toolCallId, runId);
    }
  }

  getStateByRun(runId: string | undefined): SecurityRunState | undefined {
    if (!runId) return undefined;
    return this.byRun.get(runId);
  }

  getDetectionByToolCallId(toolCallId: string | undefined): Detection | undefined {
    if (!toolCallId) return undefined;
    const runId = this.toolCallToRun.get(toolCallId);
    if (!runId) return undefined;
    const state = this.byRun.get(runId);
    return state?.detections.find((d) => d.toolCallId === toolCallId);
  }

  hasAnyDetection(runId: string | undefined): boolean {
    if (!runId) return false;
    const state = this.byRun.get(runId);
    return !!state && state.detections.length > 0;
  }

  dropRun(runId: string | undefined): void {
    if (!runId) return;
    const state = this.byRun.get(runId);
    if (state) {
      for (const id of state.interceptedToolCallIds) this.toolCallToRun.delete(id);
    }
    this.byRun.delete(runId);
  }

  dropSession(sessionKey: string | undefined, sessionId: string | undefined): void {
    if (!sessionKey && !sessionId) return;
    for (const [runId, state] of this.byRun) {
      if (
        (sessionKey && state.sessionKey === sessionKey) ||
        (sessionId && state.sessionId === sessionId)
      ) {
        for (const id of state.interceptedToolCallIds) this.toolCallToRun.delete(id);
        this.byRun.delete(runId);
      }
    }
  }

  /** For tests. */
  reset(): void {
    this.byRun.clear();
    this.toolCallToRun.clear();
  }

  /** For tests. */
  runCount(): number {
    return this.byRun.size;
  }
}
