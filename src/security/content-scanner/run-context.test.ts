import { beforeEach, describe, expect, it } from "vitest";

import type { Detection } from "./detectors.js";
import { ContentScannerRunContext } from "./run-context.js";

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

describe("ContentScannerRunContext", () => {
  let ctx: ContentScannerRunContext;

  beforeEach(() => {
    ctx = new ContentScannerRunContext();
  });

  it("creates run state lazily", () => {
    const s = ctx.ensureRun("run-1", "sess-k", "sess-1");
    expect(s.runId).toBe("run-1");
    expect(s.detections).toEqual([]);
    expect(ctx.runCount()).toBe(1);
  });

  it("records detections and indexes by toolCallId", () => {
    ctx.ensureRun("run-1");
    ctx.recordDetection("run-1", mkDetection({ toolCallId: "call-A" }));
    ctx.recordDetection(
      "run-1",
      mkDetection({ toolCallId: "call-B", class: "shell-injection" }),
    );
    expect(ctx.hasAnyDetection("run-1")).toBe(true);
    expect(ctx.getDetectionByToolCallId("call-A")?.class).toBe("prompt-injection");
    expect(ctx.getDetectionByToolCallId("call-B")?.class).toBe("shell-injection");
    expect(ctx.getStateByRun("run-1")?.detections).toHaveLength(2);
  });

  it("keeps runs isolated by runId", () => {
    ctx.recordDetection("run-1", mkDetection({ toolCallId: "a" }));
    ctx.recordDetection("run-2", mkDetection({ toolCallId: "b" }));
    expect(ctx.hasAnyDetection("run-1")).toBe(true);
    expect(ctx.hasAnyDetection("run-2")).toBe(true);
    expect(ctx.hasAnyDetection("run-404")).toBe(false);
  });

  it("dropRun clears run and unlinks tool-call index entries", () => {
    ctx.recordDetection("run-1", mkDetection({ toolCallId: "call-1" }));
    ctx.dropRun("run-1");
    expect(ctx.hasAnyDetection("run-1")).toBe(false);
    expect(ctx.getDetectionByToolCallId("call-1")).toBeUndefined();
  });

  it("dropSession removes every run under a session", () => {
    ctx.ensureRun("run-1", "sess-k", "sess-id");
    ctx.ensureRun("run-2", "sess-k", "sess-id");
    ctx.ensureRun("run-3", "other", "other-id");
    ctx.recordDetection("run-1", mkDetection({ toolCallId: "a" }));
    ctx.recordDetection("run-3", mkDetection({ toolCallId: "c" }));

    ctx.dropSession("sess-k", "sess-id");
    expect(ctx.hasAnyDetection("run-1")).toBe(false);
    expect(ctx.hasAnyDetection("run-2")).toBe(false);
    expect(ctx.hasAnyDetection("run-3")).toBe(true);
  });

  it("returns undefined for unknown inputs", () => {
    expect(ctx.hasAnyDetection(undefined)).toBe(false);
    expect(ctx.getDetectionByToolCallId(undefined)).toBeUndefined();
    expect(ctx.getDetectionByToolCallId("unknown")).toBeUndefined();
    expect(ctx.getStateByRun(undefined)).toBeUndefined();
  });
});
