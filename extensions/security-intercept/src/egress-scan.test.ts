import { describe, expect, it } from "vitest";

import { compileEgressRules, scanEgress } from "./egress-scan.js";

describe("compileEgressRules", () => {
  it("returns built-in credential + pii rules by default", () => {
    const r = compileEgressRules();
    expect(r.some((rule) => rule.kind === "aws-access-key")).toBe(true);
    expect(r.some((rule) => rule.kind === "us-ssn")).toBe(true);
    expect(r.some((rule) => rule.kind === "private-key-pem")).toBe(true);
  });

  it("disables classes when flagged off", () => {
    const r = compileEgressRules({ enableCredential: false });
    expect(r.some((rule) => rule.class === "credential-leak")).toBe(false);
    expect(r.some((rule) => rule.class === "pii-exposure")).toBe(true);
  });

  it("silently drops invalid custom patterns", () => {
    const r = compileEgressRules({ extraCredentialPatterns: ["(unterminated"] });
    expect(r.every((rule) => rule.re.source !== "(unterminated")).toBe(true);
  });
});

describe("scanEgress — no match leaves content untouched", () => {
  const rules = compileEgressRules();
  it.each([
    "Good morning, here is your meeting summary.",
    "",
    "User 12345 logged in successfully.",
  ])("benign: %s", (content) => {
    const r = scanEgress(content, rules);
    expect(r.redactedContent).toBe(content);
    expect(r.matches).toHaveLength(0);
    expect(r.criticalHit).toBe(false);
  });
});

describe("scanEgress — credential leak (soft, redacts in place)", () => {
  const rules = compileEgressRules();

  it("redacts an AWS access key", () => {
    const r = scanEgress("Here is your key: AKIAABCDEFGHIJKLMNOP and use it.", rules);
    expect(r.redactedContent).toContain("[REDACTED:aws-access-key]");
    expect(r.redactedContent).not.toContain("AKIAABCDEFGHIJKLMNOP");
    expect(r.matches.find((m) => m.kind === "aws-access-key")?.count).toBe(1);
    expect(r.criticalHit).toBe(false);
  });

  it("redacts an OpenAI-style key", () => {
    const r = scanEgress("token=sk-abcdefghijklmnopqrstuvwxyzABCDEFG1234567890", rules);
    expect(r.redactedContent).toContain("[REDACTED:openai-like-key]");
  });

  it("redacts a github PAT", () => {
    const r = scanEgress("gh auth with ghp_AAAAAAAAAAAAAAAAAAAA now", rules);
    expect(r.redactedContent).toContain("[REDACTED:github-pat]");
  });

  it("redacts password assignment forms", () => {
    const r = scanEgress("settings: password=hunter2abc", rules);
    expect(r.redactedContent).toContain("[REDACTED:password-assignment]");
  });

  it("counts multiple matches of the same kind", () => {
    const r = scanEgress("keys: AKIAABCDEFGHIJKLMNOP and AKIA1111222233334444", rules);
    expect(r.matches.find((m) => m.kind === "aws-access-key")?.count).toBe(2);
  });
});

describe("scanEgress — private key PEM (hard, triggers critical hit)", () => {
  it("flags critical and redacts the whole PEM block", () => {
    const pem =
      "Prefix\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\nSuffix";
    const r = scanEgress(pem, compileEgressRules());
    expect(r.criticalHit).toBe(true);
    expect(r.redactedContent).toContain("[REDACTED:private-key-pem]");
    expect(r.redactedContent).not.toContain("MIIEpAIBAAKCAQEA");
    expect(r.redactedContent.startsWith("Prefix")).toBe(true);
    expect(r.redactedContent.endsWith("Suffix")).toBe(true);
  });
});

describe("scanEgress — PII", () => {
  const rules = compileEgressRules();

  it("redacts a US SSN", () => {
    const r = scanEgress("SSN on file: 123-45-6789.", rules);
    expect(r.redactedContent).toContain("[REDACTED:us-ssn]");
  });

  it("redacts an email address", () => {
    const r = scanEgress("Contact alice@example.com soon.", rules);
    expect(r.redactedContent).toContain("[REDACTED:email]");
  });

  it("redacts candidate credit-card numbers", () => {
    const r = scanEgress("Card: 4111 1111 1111 1111", rules);
    expect(r.redactedContent).toContain("[REDACTED:credit-card-candidate]");
  });
});

describe("scanEgress — multi-class simultaneous hits", () => {
  it("redacts credentials and PII in the same reply", () => {
    const r = scanEgress(
      "user=alice@example.com, key=AKIAABCDEFGHIJKLMNOP, ssn=123-45-6789",
      compileEgressRules(),
    );
    expect(r.redactedContent).toContain("[REDACTED:email]");
    expect(r.redactedContent).toContain("[REDACTED:aws-access-key]");
    expect(r.redactedContent).toContain("[REDACTED:us-ssn]");
    expect(r.matches.length).toBeGreaterThanOrEqual(3);
    expect(r.criticalHit).toBe(false);
  });
});
