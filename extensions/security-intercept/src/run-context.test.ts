import { beforeEach, describe, expect, it } from "vitest";

import type { Detection } from "./detectors.js";
import {
  __resetForTests,
  __runCount,
  dropRun,
  dropSession,
  ensureRunState,
  getDetectionByToolCallId,
  getStateByRun,
  hasAnyDetection,
  recordDetection,
} from "./run-context.js";

function mkDetection(overrides: Partial<Detection> = {}): Detection {
  return {
    class: "prompt-injection",
    toolName: "web_search",
    toolCallId: "call-1",
    runId: "run-1",
    snippet: "...",
    matchedPattern: "pattern",
    timestamp: 0,
    ...overrides,
  };
}

beforeEach(() => {
  __resetForTests();
});

describe("run-context", () => {
  it("creates state lazily on ensureRunState", () => {
    const s = ensureRunState("run-1", "sess-k", "sess-1");
    expect(s.runId).toBe("run-1");
    expect(s.detections).toEqual([]);
    expect(__runCount()).toBe(1);
  });

  it("recordDetection appends to the correct run and indexes toolCallId", () => {
    ensureRunState("run-1", "sess-k");
    recordDetection("run-1", mkDetection({ toolCallId: "call-A" }));
    recordDetection("run-1", mkDetection({ toolCallId: "call-B", class: "shell-injection" }));
    const s = getStateByRun("run-1");
    expect(s?.detections).toHaveLength(2);
    expect(hasAnyDetection("run-1")).toBe(true);
    expect(getDetectionByToolCallId("call-A")?.class).toBe("prompt-injection");
    expect(getDetectionByToolCallId("call-B")?.class).toBe("shell-injection");
  });

  it("keeps runs isolated by runId", () => {
    recordDetection("run-1", mkDetection({ toolCallId: "a", runId: "run-1" }));
    recordDetection("run-2", mkDetection({ toolCallId: "b", runId: "run-2" }));
    expect(hasAnyDetection("run-1")).toBe(true);
    expect(hasAnyDetection("run-2")).toBe(true);
    expect(hasAnyDetection("run-404")).toBe(false);
  });

  it("dropRun removes the run and its tool-call index entries", () => {
    recordDetection("run-1", mkDetection({ toolCallId: "call-1" }));
    dropRun("run-1");
    expect(hasAnyDetection("run-1")).toBe(false);
    expect(getDetectionByToolCallId("call-1")).toBeUndefined();
  });

  it("dropSession removes all runs under the session", () => {
    ensureRunState("run-1", "sess-k", "sess-id");
    ensureRunState("run-2", "sess-k", "sess-id");
    ensureRunState("run-3", "other-sess-k", "other-sess-id");
    recordDetection("run-1", mkDetection({ toolCallId: "a" }));
    recordDetection("run-3", mkDetection({ toolCallId: "c" }));

    dropSession("sess-k", "sess-id");

    expect(hasAnyDetection("run-1")).toBe(false);
    expect(hasAnyDetection("run-2")).toBe(false);
    expect(hasAnyDetection("run-3")).toBe(true);
  });

  it("hasAnyDetection returns false when runId is undefined", () => {
    expect(hasAnyDetection(undefined)).toBe(false);
  });

  it("getDetectionByToolCallId returns undefined for unknown call", () => {
    expect(getDetectionByToolCallId("unknown")).toBeUndefined();
    expect(getDetectionByToolCallId(undefined)).toBeUndefined();
  });
});
