import { describe, expect, it } from "vitest";

import { compileEgressRules, scanEgress } from "./egress-scan.js";

describe("content-scanner egress — compileEgressRules", () => {
  it("returns built-in credential + pii rules by default", () => {
    const r = compileEgressRules();
    expect(r.some((rule) => rule.kind === "aws-access-key")).toBe(true);
    expect(r.some((rule) => rule.kind === "us-ssn")).toBe(true);
    expect(r.some((rule) => rule.kind === "private-key-pem")).toBe(true);
  });

  it("disables a class when its flag is false", () => {
    const r = compileEgressRules({ enablePii: false });
    expect(r.some((rule) => rule.class === "pii-exposure")).toBe(false);
    expect(r.some((rule) => rule.class === "credential-leak")).toBe(true);
  });

  it("drops invalid custom patterns silently", () => {
    const r = compileEgressRules({ extraCredentialPatterns: ["(unterminated"] });
    expect(r.every((rule) => rule.re.source !== "(unterminated")).toBe(true);
  });
});

describe("content-scanner egress — scanEgress (no match)", () => {
  const rules = compileEgressRules();
  it.each(["Good morning.", "", "User 12345 logged in."])(
    "leaves benign content untouched: %s",
    (content) => {
      const r = scanEgress(content, rules);
      expect(r.redactedContent).toBe(content);
      expect(r.matches).toHaveLength(0);
      expect(r.criticalHit).toBe(false);
    },
  );
});

describe("content-scanner egress — credential redaction (soft)", () => {
  const rules = compileEgressRules();

  it("redacts an AWS access key", () => {
    const r = scanEgress("key=AKIAABCDEFGHIJKLMNOP", rules);
    expect(r.redactedContent).toContain("[REDACTED:aws-access-key]");
    expect(r.redactedContent).not.toContain("AKIAABCDEFGHIJKLMNOP");
    expect(r.criticalHit).toBe(false);
  });

  it("redacts an OpenAI-style key", () => {
    const r = scanEgress("sk-abcdefghijklmnopqrstuvwxyzABCDEFG1234567890", rules);
    expect(r.redactedContent).toContain("[REDACTED:openai-like-key]");
  });

  it("redacts a password assignment", () => {
    const r = scanEgress("config: password=hunter2abc", rules);
    expect(r.redactedContent).toContain("[REDACTED:password-assignment]");
  });

  it("counts multiple hits of the same kind", () => {
    const r = scanEgress("AKIAABCDEFGHIJKLMNOP and AKIA1111222233334444", rules);
    expect(r.matches.find((m) => m.kind === "aws-access-key")?.count).toBe(2);
  });
});

describe("content-scanner egress — critical (hard) redaction", () => {
  it("redacts a full PEM block and flags criticalHit", () => {
    const pem =
      "Prefix\n-----BEGIN RSA PRIVATE KEY-----\nBODY\n-----END RSA PRIVATE KEY-----\nSuffix";
    const r = scanEgress(pem, compileEgressRules());
    expect(r.criticalHit).toBe(true);
    expect(r.redactedContent).toContain("[REDACTED:private-key-pem]");
    expect(r.redactedContent.startsWith("Prefix")).toBe(true);
    expect(r.redactedContent.endsWith("Suffix")).toBe(true);
  });
});

describe("content-scanner egress — pii", () => {
  const rules = compileEgressRules();

  it("redacts a US SSN", () => {
    expect(scanEgress("SSN: 123-45-6789", rules).redactedContent).toContain("[REDACTED:us-ssn]");
  });

  it("redacts an email", () => {
    expect(scanEgress("alice@example.com", rules).redactedContent).toContain("[REDACTED:email]");
  });

  it("redacts candidate credit card numbers", () => {
    expect(scanEgress("card: 4111 1111 1111 1111", rules).redactedContent).toContain(
      "[REDACTED:credit-card-candidate]",
    );
  });
});
